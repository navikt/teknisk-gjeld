package no.nav.tekniskgjeld

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse

// Leser hvilke pakker et repo avhenger av DIREKTE, fra manifestfilene i roten av repoet.
// Bare navn (system + navn) trengs: versjonen som faktisk kjører kommer fra SBOM-en.
// Alt i SBOM-en som ikke står her regnes som transitivt.

private val github: HttpClient = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).build()

/** Filer i roten av repoet -> funksjon som gir (system, navn) for direkte avhengigheter. */
private val MANIFESTS: Map<String, (String) -> Set<Pair<String, String>>> = mapOf(
    "package.json" to ::npmDirect,
    "go.mod" to ::goDirect,
    "gradle/libs.versions.toml" to ::gradleCatalogDirect,
    "build.gradle.kts" to ::gradleBuildDirect,
    "build.gradle" to ::gradleBuildDirect,
    "pom.xml" to ::pomDirect,
    "requirements.txt" to ::requirementsDirect,
    "pyproject.toml" to ::pyprojectDirect,
)

/** Direkte avhengigheter for et repo ("navikt/x"), eller null hvis ingen manifestfiler ble funnet/lest. */
fun fetchDirectDependencies(repository: String): Set<Pair<String, String>>? {
    val repo = repository.removePrefix("https://github.com/").removeSuffix(".git").trim('/')
    var found = false
    val direct = MANIFESTS.flatMap { (path, parse) ->
        // HEAD = repoets standard-branch
        val response = github.send(
            HttpRequest.newBuilder(URI("https://raw.githubusercontent.com/$repo/HEAD/$path")).build(),
            HttpResponse.BodyHandlers.ofString(),
        )
        if (response.statusCode() != 200) return@flatMap emptySet()
        found = true
        runCatching { parse(response.body()) }.getOrDefault(emptySet())
    }.toSet()
    return if (found) direct else null
}

// --- npm ---

private fun npmDirect(text: String): Set<Pair<String, String>> {
    val json = Json.parseToJsonElement(text).jsonObject
    return listOf("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
        .flatMap { (json[it] as? JsonObject)?.keys.orEmpty() }
        .map { "NPM" to it }.toSet()
}

// --- Go: require-linjer uten "// indirect" ---

private fun goDirect(text: String): Set<Pair<String, String>> {
    val result = mutableSetOf<Pair<String, String>>()
    var inBlock = false
    for (raw in text.lines()) {
        val line = raw.trim()
        when {
            line.startsWith("require (") -> inBlock = true
            inBlock && line == ")" -> inBlock = false
            (inBlock || line.startsWith("require ")) && !line.contains("// indirect") -> {
                val parts = line.removePrefix("require ").substringBefore("//").trim().split(Regex("\\s+"))
                if (parts.size == 2) result += "GO" to parts[0]
            }
        }
    }
    return result
}

// --- Gradle / Maven -> "group:artifact" ---

// gradle/libs.versions.toml: module = "g:a", group = "g" + name = "a", eller "g:a:v"
private fun gradleCatalogDirect(text: String): Set<Pair<String, String>> {
    val libraries = text.substringAfter("[libraries]", "").substringBefore("\n[")
    return libraries.lines().mapNotNull { line ->
        val fields = Regex("""([\w.]+)\s*=\s*"([^"]*)"""").findAll(line).associate { it.groupValues[1] to it.groupValues[2] }
        val inline = Regex("""=\s*"([\w.-]+:[\w.-]+)(:[^"]*)?"""").find(line)?.groupValues?.get(1)
        (fields["module"] ?: fields["group"]?.let { g -> fields["name"]?.let { "$g:$it" } } ?: inline)?.let { "MAVEN" to it }
    }.toSet()
}

// build.gradle(.kts): "group:artifact:version" eller "group:artifact"
private fun gradleBuildDirect(text: String): Set<Pair<String, String>> =
    Regex("""["']([\w.-]+):([\w.-]+)(:[^"']*)?["']""").findAll(text)
        .map { "MAVEN" to "${it.groupValues[1]}:${it.groupValues[2]}" }.toSet()

private fun pomDirect(text: String): Set<Pair<String, String>> =
    Regex("""(?s)<dependency>.*?<groupId>\s*([^<\s]+)\s*</groupId>.*?<artifactId>\s*([^<\s]+)\s*</artifactId>""")
        .findAll(text).map { "MAVEN" to "${it.groupValues[1]}:${it.groupValues[2]}" }.toSet()

// --- Python ---

private fun pypi(name: String) = "PYPI" to name.lowercase().replace(Regex("[-_.]+"), "-")

private fun pythonName(requirement: String) =
    Regex("""^\s*([A-Za-z0-9][A-Za-z0-9._-]*)""").find(requirement)?.groupValues?.get(1)

private fun requirementsDirect(text: String): Set<Pair<String, String>> =
    text.lines().map { it.substringBefore("#").trim() }
        .filter { it.isNotEmpty() && !it.startsWith("-") }
        .mapNotNull { pythonName(it)?.let(::pypi) }.toSet()

// pyproject.toml: lister med strenger (PEP 621 dependencies, optional-dependencies, dependency-groups)
// og Poetry-seksjoner ([tool.poetry.dependencies] navn = "...")
private fun pyprojectDirect(text: String): Set<Pair<String, String>> {
    val lists = Regex("""(?sm)^\s*[\w-]+\s*=\s*\[(.*?)]\s*$""").findAll(text).flatMap { block ->
        Regex(""""([^"]+)"""").findAll(block.groupValues[1]).mapNotNull { pythonName(it.groupValues[1]) }
    }
    var section = ""
    val poetry = text.lines().mapNotNull { raw ->
        val line = raw.substringBefore("#").trim()
        if (line.startsWith("[")) section = line.trim('[', ']')
        val isPoetryDeps = section.startsWith("tool.poetry") && section.endsWith("dependencies")
        if (!isPoetryDeps || line.startsWith("[") || !line.contains("=")) return@mapNotNull null
        line.substringBefore("=").trim().takeIf { it != "python" }
    }
    return (lists + poetry).map(::pypi).toSet()
}
