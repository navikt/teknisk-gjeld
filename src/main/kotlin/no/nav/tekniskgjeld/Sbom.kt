package no.nav.tekniskgjeld

import com.google.auth.oauth2.GoogleCredentials
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import java.net.URI
import java.net.URLDecoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.util.Base64

// Henter SBOM-er for et teams workloads:
//   1. Nais API: hvilke images teamet kjører (navn + digest + SBOM-status)
//   2. Artifact Registry: CycloneDX-SBOM-en som nais/attest-sign har lagt ved imaget (cosign attestation)
//   3. purl -> Dependency, slik at vi kan slå opp i deps.dev

// Lokalt kan man bruke `nais api proxy` (din egen innlogging) med NAIS_API_URL=http://localhost:4242/graphql
val NAIS_API_URL: String = System.getenv("NAIS_API_URL") ?: "https://console.nav.cloud.nais.io/graphql"
const val CYCLONEDX_PREDICATE = "https://cyclonedx.org/bom"

/** repositories = GitHub-repoene ("navikt/x") som deployet imaget, ifølge Nais API. */
data class Image(val name: String, val digest: String, val workloads: List<String>, val repositories: Set<String>)

data class Sbom(val dependencies: List<Dependency>, val skipped: Map<String, Int>)

// HTTP/1.1: Java prøver ellers h2c-upgrade over http://, som `nais api proxy` svarer 502 på.
private val http: HttpClient = HttpClient.newBuilder()
    .version(HttpClient.Version.HTTP_1_1)
    .followRedirects(HttpClient.Redirect.NEVER)
    .build()

// --- 1. Nais API ---

private val WORKLOAD_FIELDS = """
    nodes {
      name
      teamEnvironment { environment { name } }
      image { name digest sbom { status } }
      deployments(first: 1) { nodes { repository } }
    }
"""
private val IMAGES_QUERY = $$"""
    query($team: Slug!) {
      team(slug: $team) {
        applications(first: 100) { $$WORKLOAD_FIELDS }
        jobs(first: 100) { $$WORKLOAD_FIELDS }
      }
    }
""".trimIndent()

/** Henter unike images (på digest) med SBOM-status READY. Workloads uten SBOM skrives ut og hoppes over. */
fun fetchImages(team: String, naisToken: String?, filter: String?): List<Image> {
    val body = buildJsonObject {
        put("query", IMAGES_QUERY)
        putJsonObject("variables") { put("team", team) }
    }
    val request = HttpRequest.newBuilder(URI(NAIS_API_URL))
        .header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
    naisToken?.let { request.header("Authorization", "Bearer $it") }
    val response = http.send(request.build(), HttpResponse.BodyHandlers.ofString())
    if (response.statusCode() != 200) fail("Nais API svarte HTTP ${response.statusCode()}: ${response.body().take(300)}")

    val json = Json.parseToJsonElement(response.body()).jsonObject
    (json["errors"] as? JsonArray)?.let { fail("Nais API-feil: $it") }
    val teamJson = json["data"]?.jsonObject?.get("team") as? JsonObject ?: fail("Fant ikke team '$team' i Nais API")

    data class Workload(
        val name: String, val env: String, val image: String, val digest: String?, val sbomStatus: String, val repository: String?,
    )

    val workloads = listOf("applications", "jobs").flatMap { kind ->
        ((teamJson[kind] as? JsonObject)?.get("nodes") as? JsonArray).orEmpty().map { node ->
            val n = node.jsonObject
            val image = n["image"]!!.jsonObject
            Workload(
                name = n.str("name")!!,
                env = n["teamEnvironment"]?.jsonObject?.get("environment")?.jsonObject?.str("name") ?: "?",
                image = image.str("name")!!,
                digest = image.str("digest"),
                sbomStatus = image["sbom"]?.jsonObject?.str("status") ?: "UKJENT",
                repository = (n["deployments"] as? JsonObject)?.get("nodes")?.jsonArray?.firstOrNull()?.jsonObject?.str("repository"),
            )
        }
    }.filter { filter == null || it.name.contains(filter) }

    workloads.filter { it.sbomStatus != "READY" || it.digest == null }.forEach {
        println("  hopper over ${it.name} (${it.env}): SBOM-status ${it.sbomStatus}${if (it.digest == null) ", mangler digest" else ""}")
    }

    return workloads.filter { it.sbomStatus == "READY" && it.digest != null }
        .groupBy { it.image to it.digest!! }
        .map { (key, same) ->
            val labels = same.groupBy { it.name }.map { (name, envs) -> "$name (${envs.joinToString(", ") { it.env }})" }
            Image(key.first, key.second, labels, same.mapNotNull { it.repository }.toSet())
        }
}

// --- 2. Artifact Registry ---

private val googleCredentials by lazy {
    GoogleCredentials.getApplicationDefault().createScoped("https://www.googleapis.com/auth/cloud-platform")
}

private fun googleToken(): String {
    googleCredentials.refreshIfExpired()
    return googleCredentials.accessToken?.tokenValue
        ?: error("Fikk ikke access token fra Google. Kjør: gcloud auth application-default login")
}

/**
 * GET mot registeret. Redirects følges manuelt (som curl -L): Location kan være relativ.
 * Authorization sendes bare videre hvis redirecten går til samme vert (ikke til f.eks. en signert GCS-URL).
 */
private fun registryGet(url: String, accept: String? = null): String? {
    val token = googleToken()
    fun send(uri: URI, withAuth: Boolean): HttpResponse<String> {
        val request = HttpRequest.newBuilder(uri)
        if (withAuth) request.header("Authorization", "Bearer $token")
        accept?.let { request.header("Accept", it) }
        return http.send(request.build(), HttpResponse.BodyHandlers.ofString())
    }

    val original = URI(url)
    var uri = original
    var response = send(uri, withAuth = true)
    repeat(5) {
        if (response.statusCode() !in 300..399) return@repeat
        uri = uri.resolve(response.headers().firstValue("Location").orElseThrow())
        response = send(uri, withAuth = uri.host == original.host)
    }
    return when (response.statusCode()) {
        200 -> response.body()
        404 -> null
        else -> error("Registeret svarte HTTP ${response.statusCode()} for $url: ${response.body().take(200)}")
    }
}

private const val OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"

/** Henter CycloneDX-SBOM-en for et image. Prøver referrers (cosign v3) først, deretter .att-tagg (eldre cosign). */
fun fetchSbom(image: Image): Sbom? {
    // "europe-north1-docker.pkg.dev/prosjekt/team/app" -> "https://europe-north1-docker.pkg.dev/v2/prosjekt/team/app"
    val base = "https://${image.name.substringBefore("/")}/v2/${image.name.substringAfter("/")}"

    val candidates = buildList {
        // cosign v3: attestasjoner er OCI-referrers. Annotasjonene kan være misvisende, så vi sjekker innholdet i alle.
        registryGet("$base/referrers/${image.digest}")?.let { index ->
            Json.parseToJsonElement(index).jsonObject["manifests"]?.jsonArray?.forEach { add(it.jsonObject.str("digest")!!) }
        }
        // Eldre cosign: tagg "sha256-<hash>.att"
        add(image.digest.replace(":", "-") + ".att")
    }

    for (manifestRef in candidates) {
        val manifest = registryGet("$base/manifests/$manifestRef", OCI_MANIFEST) ?: continue
        val layers = Json.parseToJsonElement(manifest).jsonObject["layers"]?.jsonArray.orEmpty()
        for (layer in layers) {
            val blob = registryGet("$base/blobs/${layer.jsonObject.str("digest")}") ?: continue
            val statement = decodeStatement(blob) ?: continue
            if (statement.str("predicateType") == CYCLONEDX_PREDICATE) {
                return parseCycloneDx(statement["predicate"]!!.jsonObject)
            }
        }
    }
    return null
}

/** Blob er enten en sigstore-bundle ({dsseEnvelope: {payload}}) eller en ren DSSE-envelope ({payload}). */
private fun decodeStatement(blob: String): JsonObject? = runCatching {
    val json = Json.parseToJsonElement(blob).jsonObject
    val envelope = json["dsseEnvelope"]?.jsonObject ?: json
    val payload = envelope.str("payload") ?: return null
    Json.parseToJsonElement(String(Base64.getDecoder().decode(payload))).jsonObject
}.getOrNull()

// --- 3. CycloneDX / purl ---

fun parseCycloneDx(bom: JsonObject): Sbom {
    val skipped = mutableMapOf<String, Int>()
    val deps = bom["components"]?.jsonArray.orEmpty().mapNotNull { component ->
        val purl = component.jsonObject.str("purl")
        val dep = purl?.let(::purlToDependency)
        if (dep == null) {
            val type = purl?.removePrefix("pkg:")?.substringBefore("/") ?: "uten purl"
            skipped.merge(type, 1, Int::plus)
        }
        dep
    }.distinct()
    return Sbom(deps, skipped)
}

/**
 * "pkg:golang/github.com/foo/bar@v1.2.3"    -> GO    github.com/foo/bar  v1.2.3
 * "pkg:npm/%40navikt/ds-react@8.20.1"       -> NPM   @navikt/ds-react    8.20.1
 * "pkg:maven/io.ktor/ktor-server-core@3.0" -> MAVEN io.ktor:ktor-server-core 3.0
 * Typer deps.dev ikke har (apk, deb, rpm, ...) gir null.
 */
fun purlToDependency(purl: String): Dependency? {
    val p = purl.removePrefix("pkg:").substringBefore("?").substringBefore("#")
    val type = p.substringBefore("/")
    val rest = p.substringAfter("/")
    val version = decode(rest.substringAfterLast("@", ""))
    val path = rest.substringBeforeLast("@").split("/").map(::decode)
    if (version.isEmpty() || version == "(devel)") return null

    return when (type) {
        "golang" -> path.joinToString("/").takeIf { it != "stdlib" }?.let { Dependency("GO", it, version) }
        "npm" -> Dependency("NPM", path.joinToString("/"), version)
        "maven" -> if (path.size >= 2) Dependency("MAVEN", "${path[0]}:${path[1]}", version) else null
        "pypi" -> Dependency("PYPI", path.last().lowercase().replace(Regex("[-_.]+"), "-"), version)
        "cargo" -> Dependency("CARGO", path.last(), version)
        "nuget" -> Dependency("NUGET", path.last(), version)
        else -> null
    }
}

private fun decode(s: String) = URLDecoder.decode(s.replace("+", "%2B"), Charsets.UTF_8)

private fun JsonObject.str(key: String): String? = runCatching { this[key]?.jsonPrimitive?.contentOrNull }.getOrNull()
