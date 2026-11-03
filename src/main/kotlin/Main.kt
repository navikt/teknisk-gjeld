import com.google.cloud.bigquery.BigQueryOptions
import com.google.cloud.bigquery.JobInfo
import com.google.cloud.bigquery.JobStatistics
import com.google.cloud.bigquery.QueryJobConfiguration
import com.google.cloud.bigquery.QueryParameterValue
import java.time.Duration
import java.time.Instant
import kotlin.system.exitProcess

// Sikring: spørringen avbrytes av BigQuery hvis den ville skannet mer enn dette.
// En kjøring for hele appsec-teamet (~1100 pakker) skanner ca. 6 GB.
const val MAX_GB_BILLED = 10L

/** system = deps.dev-økosystem (NPM, MAVEN, GO, PYPI, CARGO, NUGET). */
data class Dependency(val system: String, val name: String, val version: String)

data class PackageVersion(val version: String, val published: Instant?, val isRelease: Boolean, val ordinal: Long)

/** direct = true/false hvis vi fant manifestfiler i repoet, null hvis ukjent. */
data class Result(val dep: Dependency, val latest: String?, val libyear: Double?, val direct: Boolean?)

data class ImageReport(val image: Image, val results: List<Result>?, val skipped: Map<String, Int>, val directKnown: Boolean)

fun main(args: Array<String>) {
    val usage = "Bruk: ./gradlew run --args=\"<team> <gcp-prosjekt> [app-filter]\" (med NAIS_API_TOKEN satt)"
    val team = args.getOrNull(0) ?: fail(usage)
    val project = args.getOrNull(1) ?: System.getenv("GCP_PROJECT") ?: fail(usage)
    val filter = args.getOrNull(2)
    // Token trengs ikke via `nais api proxy` (NAIS_API_URL=http://localhost:...), der brukes din egen innlogging.
    val viaProxy = NAIS_API_URL.startsWith("http://localhost")
    val naisToken = if (viaProxy) null else System.getenv("NAIS_API_TOKEN")?.trim()?.takeIf { it.isNotEmpty() }
    if (naisToken == null && !viaProxy) {
        fail("Sett NAIS_API_TOKEN, eller kjør `nais api proxy` og sett NAIS_API_URL=http://localhost:4242/graphql")
    }

    println("Henter workloads for team $team fra Nais API ($NAIS_API_URL) ...")
    val images = fetchImages(team, naisToken, filter)
    if (images.isEmpty()) fail("Fant ingen workloads med SBOM.")

    println("Henter SBOM for ${images.size} images fra Artifact Registry ...")
    val sboms = images.associateWith { image ->
        runCatching { fetchSbom(image) }
            .onFailure { println("  feil for ${image.workloads.first()}: ${it.message}") }
            .getOrNull()
    }

    val allDeps = sboms.values.filterNotNull().flatMap { it.dependencies }.distinct()
    if (allDeps.isEmpty()) fail("Ingen pakker å slå opp i deps.dev.")

    println("Spør deps.dev i BigQuery om ${allDeps.map { it.system to it.name }.distinct().size} pakker (fakturert til $project) ...")
    val versions = queryDepsDev(project, allDeps)

    val repositories = images.flatMap { it.repositories }.distinct()
    println("Leser direkte avhengigheter fra ${repositories.size} repoer på GitHub ...")
    val directByRepo = repositories.associateWith { repo ->
        runCatching { fetchDirectDependencies(repo) }.getOrNull()
            .also { if (it == null) println("  fant ingen manifestfiler i $repo (privat repo, eller filer i undermappe?)") }
    }

    val reports = images.map { image ->
        val sbom = sboms[image]
        // Direkte = står i manifestfilene til minst ett av repoene som deployer imaget.
        val directSets = image.repositories.mapNotNull { directByRepo[it] }
        val direct = if (directSets.isEmpty()) null else directSets.flatten().toSet()
        ImageReport(
            image = image,
            results = sbom?.dependencies?.map { dep ->
                calculate(dep, versions[dep.system to dep.name].orEmpty(), direct?.contains(dep.system to dep.name))
            },
            skipped = sbom?.skipped.orEmpty(),
            directKnown = direct != null,
        )
    }
    printReport(team, reports)
}

fun queryDepsDev(project: String, deps: List<Dependency>): Map<Pair<String, String>, List<PackageVersion>> {
    val bigquery = BigQueryOptions.newBuilder().setProjectId(project).build().service

    // Steg 1: finn siste snapshot. Liten tabell, nesten gratis.
    val snapshot = bigquery.query(
        QueryJobConfiguration.newBuilder("SELECT MAX(Time) AS Time FROM `bigquery-public-data.deps_dev_v1.Snapshots`")
            .setMaximumBytesBilled(MAX_GB_BILLED * 1_000_000_000)
            .build(),
    ).iterateAll().first()["Time"].timestampValue

    // Steg 2: spør selve tabellen med fast SnapshotAt, slik at BigQuery bare leser den ene snapshoten.
    // (View-et PackageVersionsLatest bruker en subquery og skanner derfor mye mer.)
    val sql = """
        SELECT System, Name, Version, UpstreamPublishedAt, VersionInfo.IsRelease AS IsRelease, VersionInfo.Ordinal AS Ordinal
        FROM `bigquery-public-data.deps_dev_v1.PackageVersions`
        WHERE SnapshotAt = @snapshot AND System IN UNNEST(@systems) AND Name IN UNNEST(@names)
    """.trimIndent()
    val systems = deps.map { it.system }.distinct().toTypedArray()
    val names = deps.map { it.name }.distinct().toTypedArray()
    val config = QueryJobConfiguration.newBuilder(sql)
        .addNamedParameter("snapshot", QueryParameterValue.timestamp(snapshot))
        .addNamedParameter("systems", QueryParameterValue.array(systems, String::class.java))
        .addNamedParameter("names", QueryParameterValue.array(names, String::class.java))
        .setMaximumBytesBilled(MAX_GB_BILLED * 1_000_000_000)
        .build()

    val job = bigquery.create(JobInfo.of(config)).waitFor()
    job.status.error?.let { fail("BigQuery-feil: ${it.message}") }
    val gb = (job.getStatistics<JobStatistics.QueryStatistics>().totalBytesBilled ?: 0L) / 1e9
    println("BigQuery skannet %.2f GB".format(gb))

    return job.getQueryResults().iterateAll().groupBy(
        { it["System"].stringValue to it["Name"].stringValue },
        {
            val published = it["UpstreamPublishedAt"]
            // VersionInfo kan mangle for enkelte versjoner -> regnes ikke som release.
            val isRelease = it["IsRelease"]
            val ordinal = it["Ordinal"]
            PackageVersion(
                version = it["Version"].stringValue,
                published = if (published.isNull) null else Instant.EPOCH.plusNanos(published.timestampValue * 1000),
                isRelease = !isRelease.isNull && isRelease.booleanValue,
                ordinal = if (ordinal.isNull) Long.MIN_VALUE else ordinal.longValue,
            )
        },
    )
}

fun calculate(dep: Dependency, versions: List<PackageVersion>, direct: Boolean?): Result {
    val used = versions.find { it.version == dep.version }
        ?: versions.find { sameVersion(it.version, dep.version) }
    val latest = versions.filter { it.isRelease && isStable(dep.system, it.version) }.maxByOrNull { it.ordinal }
    val libyear = if (used?.published != null && latest?.published != null) {
        val days = Duration.between(used.published, latest.published).toDays().coerceAtLeast(0)
        days / 365.25
    } else {
        null
    }
    return Result(dep, latest?.version, libyear, direct)
}

// Ord i versjonsstrenger som betyr forhåndsversjon. deps.dev sin IsRelease slipper gjennom f.eks. PyPI "1.0.0.dev6".
// Merk: "RELEASE", "Final", "GA", "jre", "android", "post" o.l. er stabile og står derfor ikke her.
private val PRERELEASE_WORDS = setOf(
    "a", "alpha", "b", "beta", "c", "rc", "cr", "m", "milestone", "pre", "preview", "dev", "snapshot",
    "canary", "nightly", "next", "ea", "experimental", "insiders", "eap",
)

/** Siste "stabile" versjon: ingen alpha/beta/rc/dev/canary osv. Semver-økosystemer: alt med "-" er pre-release. */
fun isStable(system: String, version: String): Boolean {
    if (system in setOf("NPM", "GO", "CARGO", "NUGET") && version.contains('-')) return false
    return Regex("[a-zA-Z]+").findAll(version.removePrefix("v")).none { it.value.lowercase() in PRERELEASE_WORDS }
}

// "2.31" == "2.31.0" og "v1.2.3" == "1.2.3"
fun sameVersion(a: String, b: String): Boolean {
    fun norm(v: String) = v.removePrefix("v").split(".").dropLastWhile { it == "0" }.joinToString(".")
    return a.isNotEmpty() && b.isNotEmpty() && norm(a) == norm(b)
}

// --- Visning ---

const val RESET = "\u001B[0m"
const val BOLD = "\u001B[1m"
const val DIM = "\u001B[2m"
const val RED = "\u001B[31m"
const val GREEN = "\u001B[32m"
const val YELLOW = "\u001B[33m"

fun color(libyear: Double) = when {
    libyear < 0.5 -> GREEN
    libyear < 2.0 -> YELLOW
    else -> RED
}

fun libyears(value: Double?, width: Int = 10) =
    if (value == null) DIM + "-".padStart(width) + RESET else color(value) + "%${width}.2f".format(value) + RESET

fun List<Result>.libyearSum() = sumOf { it.libyear ?: 0.0 }

fun printReport(team: String, reports: List<ImageReport>) {
    val workloadCount = reports.sumOf { it.image.workloads.size }
    val labelWidth = maxOf(reports.flatMap { it.image.workloads }.maxOf { it.length }, 8)

    println()
    println("${BOLD}Teknisk gjeld for team $team$RESET ${DIM}($workloadCount apper, ${reports.size} unike images)$RESET")
    println(DIM + "Direkte = står i package.json/go.mod/gradle/pom/pyproject i repoet som deployer appen. Resten er transitive." + RESET)
    println(DIM + "Siste versjon = siste stabile release (ingen alpha/beta/rc/dev/canary/snapshot)." + RESET)
    println()
    println(
        BOLD + "App".padEnd(labelWidth) + "  " + "Pakker".padStart(7) + "Direkte".padStart(9) + "Utdatert".padStart(10) +
            "Ukjent".padStart(8) + "Lib.dir.".padStart(10) + "Lib.tot.".padStart(10) + RESET,
    )
    println("-".repeat(labelWidth + 2 + 7 + 9 + 10 + 8 + 10 + 10))

    // Sorter på gjeld i direkte avhengigheter (det teamet kan gjøre noe med), deretter totalt.
    val sorted = reports.sortedWith(
        compareByDescending<ImageReport> { r -> r.results?.filter { it.direct == true }?.libyearSum() ?: -1.0 }
            .thenByDescending { r -> r.results?.libyearSum() ?: -1.0 },
    )
    for (report in sorted) {
        val labels = report.image.workloads
        val results = report.results
        if (results == null) {
            println(labels.first().padEnd(labelWidth) + "  " + DIM + "ingen SBOM funnet i registeret" + RESET)
            labels.drop(1).forEach { println(DIM + it + RESET) }
            continue
        }

        val direct = results.filter { it.direct == true }
        val known = results.mapNotNull { it.libyear }
        println(
            labels.first().padEnd(labelWidth) + "  " +
                results.size.toString().padStart(7) +
                (if (report.directKnown) direct.size.toString() else "?").padStart(9) +
                known.count { it > 0 }.toString().padStart(10) +
                (results.size - known.size).toString().padStart(8) +
                libyears(if (report.directKnown) direct.libyearSum() else null) +
                libyears(results.libyearSum()),
        )
        labels.drop(1).forEach { println(DIM + it + RESET) }

        fun worst(title: String, list: List<Result>, n: Int) {
            val top = list.filter { (it.libyear ?: 0.0) > 0 }.sortedByDescending { it.libyear }.take(n)
            if (top.isEmpty()) return
            println(DIM + "    $title" + RESET)
            top.forEach { r ->
                println(DIM + "      ${r.dep.name} ${r.dep.version} → ${r.latest}" + RESET + "  " + color(r.libyear!!) + "%.2f".format(r.libyear) + RESET)
            }
        }
        if (report.directKnown) {
            worst("direkte:", direct, 5)
            worst("transitive:", results.filter { it.direct == false }, 3)
        } else {
            worst("(repo ukjent, kan ikke skille direkte/transitive):", results, 5)
        }
    }

    val all = reports.mapNotNull { it.results }.flatten()
    val allDirect = all.filter { it.direct == true }
    val total = all.libyearSum()
    val skipped = reports.flatMap { it.skipped.entries }.groupBy({ it.key }, { it.value }).mapValues { it.value.sum() }

    println()
    println(BOLD + "Totalt: " + color(total / maxOf(reports.size, 1)) + "%.2f libyears".format(total) + RESET +
        "  (direkte: " + "%.2f".format(allDirect.libyearSum()) +
        ", transitive: " + "%.2f".format(all.filter { it.direct == false }.libyearSum()) +
        ", repo ukjent: " + "%.2f".format(all.filter { it.direct == null }.libyearSum()) + ")")
    println("${all.size} pakker (${allDirect.size} direkte), ${all.count { (it.libyear ?: 0.0) > 0 }} utdaterte, ${all.count { it.libyear == null }} ukjente (ikke funnet i deps.dev)")
    if (skipped.isNotEmpty()) {
        println(DIM + "Ikke i deps.dev, hoppet over: " + skipped.entries.joinToString { "${it.value} ${it.key}" } + RESET)
    }
}

fun fail(message: String): Nothing {
    System.err.println(message)
    exitProcess(1)
}
