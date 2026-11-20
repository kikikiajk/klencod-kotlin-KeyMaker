/*
 * مولّد مفتاح التوقيع - Jetpack Compose + BouncyCastle
 *
 * app/build.gradle.kts  (dependencies):
 *   implementation(platform("androidx.compose:compose-bom:2024.09.00"))
 *   implementation("androidx.compose.material3:material3")
 *   implementation("androidx.compose.ui:ui")
 *   implementation("androidx.activity:activity-compose:1.9.2")
 *   implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
 *   implementation("org.bouncycastle:bcpkix-jdk18on:1.78.1")
 *
 * android { packaging { resources { excludes += "META-INF/versions/**" } } }
 *
 * لا يحتاج أي صلاحية تخزين: الحفظ يتم عبر نافذة اختيار المكان (SAF).
 */
package com.apkmaker.keygen

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

// ---------- المنطق ----------

data class KeyForm(
    val alias: String = "",
    val password: String = "",
    val years: String = "25",
    val name: String = "",
    val org: String = "",
    val unit: String = "",
    val city: String = "",
    val state: String = "",
    val country: String = "IQ",
)

class GeneratedKey(
    val alias: String,
    val bytes: ByteArray,
    val sha256: String,
    val validUntil: String,
)

/** يرجع نص الخطأ أو null إذا كل شي تمام. */
fun validate(f: KeyForm): String? = when {
    f.alias.isBlank() -> "اكتب اسم المفتاح (Alias)."
    f.password.length < 6 -> "كلمة السر لازم تكون 6 أحرف على الأقل."
    (f.years.toIntOrNull() ?: 0) !in 1..100 -> "مدة الصلاحية لازم تكون بين 1 و 100 سنة."
    f.name.isBlank() -> "اكتب اسمك أو اسم المطوّر."
    f.country.length != 2 -> "رمز الدولة حرفين، مثل IQ."
    else -> null
}

fun generateKey(f: KeyForm): GeneratedKey {
    val bc = BouncyCastleProvider()
    val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048, SecureRandom()) }.generateKeyPair()

    val dn = X500NameBuilder(BCStyle.INSTANCE).apply {
        addRDN(BCStyle.CN, f.name.trim())
        if (f.unit.isNotBlank()) addRDN(BCStyle.OU, f.unit.trim())
        if (f.org.isNotBlank()) addRDN(BCStyle.O, f.org.trim())
        if (f.city.isNotBlank()) addRDN(BCStyle.L, f.city.trim())
        if (f.state.isNotBlank()) addRDN(BCStyle.ST, f.state.trim())
        addRDN(BCStyle.C, f.country.trim().uppercase())
    }.build()

    val from = Date()
    val to = Date(from.time + f.years.toLong() * 365L * 24 * 60 * 60 * 1000)
    val signer = JcaContentSignerBuilder("SHA256withRSA").setProvider(bc).build(pair.private)
    val cert = JcaX509CertificateConverter().setProvider(bc).getCertificate(
        JcaX509v3CertificateBuilder(dn, BigInteger(64, SecureRandom()), from, to, dn, pair.public).build(signer)
    )

    val pass = f.password.toCharArray()
    val ks = KeyStore.getInstance("PKCS12").apply { load(null, null) }
    ks.setKeyEntry(f.alias.trim(), pair.private, pass, arrayOf(cert))
    val out = ByteArrayOutputStream().also { ks.store(it, pass) }

    val sha = MessageDigest.getInstance("SHA-256").digest(cert.encoded)
        .joinToString(":") { "%02X".format(it) }
    val until = SimpleDateFormat("yyyy-MM-dd", Locale.US).format(to)
    return GeneratedKey(f.alias.trim(), out.toByteArray(), sha, until)
}

// ---------- الواجهة ----------

private val Teal = Color(0xFF0F4C5C)
private val Brass = Color(0xFFE09F3E)
private val Paper = Color(0xFFF4F7F8)
private val Ink = Color(0xFF14232B)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(
                colorScheme = lightColorScheme(primary = Teal, secondary = Brass, background = Paper, onBackground = Ink)
            ) {
                CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
                    KeyMakerScreen()
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KeyMakerScreen() {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val snack = remember { SnackbarHostState() }

    var form by remember { mutableStateOf(KeyForm()) }
    var result by remember { mutableStateOf<GeneratedKey?>(null) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    val saver = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/x-pkcs12")
    ) { uri ->
        val key = result ?: return@rememberLauncherForActivityResult
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            val ok = withContext(Dispatchers.IO) {
                runCatching { ctx.contentResolver.openOutputStream(uri)!!.use { it.write(key.bytes) } }.isSuccess
            }
            snack.showSnackbar(if (ok) "انحفظ المفتاح." else "ما قدرت أحفظ الملف، جرّب مكان ثاني.")
        }
    }

    Scaffold(
        containerColor = Paper,
        snackbarHost = { SnackbarHost(snack) },
        topBar = {
            TopAppBar(
                title = { Text("مفتاح توقيع جديد", fontWeight = FontWeight.Bold) },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = Teal, titleContentColor = Color.White),
            )
        },
    ) { pad ->
        Column(
            Modifier.padding(pad).verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Section("بيانات المفتاح") {
                Field("اسم المفتاح (Alias)", form.alias) { form = form.copy(alias = it) }
                Field("كلمة السر", form.password, password = true) { form = form.copy(password = it) }
                Field("الصلاحية بالسنوات", form.years, number = true) { form = form.copy(years = it) }
            }
            Section("بيانات الشهادة") {
                Field("الاسم الكامل", form.name) { form = form.copy(name = it) }
                Field("المؤسسة (اختياري)", form.org) { form = form.copy(org = it) }
                Field("القسم (اختياري)", form.unit) { form = form.copy(unit = it) }
                Field("المدينة (اختياري)", form.city) { form = form.copy(city = it) }
                Field("المحافظة (اختياري)", form.state) { form = form.copy(state = it) }
                Field("رمز الدولة", form.country) { form = form.copy(country = it.take(2)) }
            }

            error?.let { Text(it, color = MaterialTheme.colorScheme.error) }

            Button(
                onClick = {
                    error = validate(form)
                    if (error == null) {
                        busy = true
                        scope.launch {
                            result = runCatching { withContext(Dispatchers.Default) { generateKey(form) } }
                                .onFailure { error = "صار خطأ أثناء الإنشاء: ${it.message}" }
                                .getOrNull()
                            busy = false
                        }
                    }
                },
                enabled = !busy,
                modifier = Modifier.fillMaxWidth().height(52.dp),
                shape = RoundedCornerShape(14.dp),
            ) {
                if (busy) CircularProgressIndicator(Modifier.size(22.dp), color = Color.White, strokeWidth = 2.dp)
                else Text("إنشاء المفتاح", fontSize = 16.sp)
            }

            result?.let { key ->
                Section("تم الإنشاء") {
                    Info("الاسم", key.alias)
                    Info("ينتهي بتاريخ", key.validUntil)
                    Info("البصمة SHA-256", key.sha256)
                    Button(
                        onClick = { saver.launch("${key.alias}.p12") },
                        modifier = Modifier.fillMaxWidth().height(52.dp),
                        shape = RoundedCornerShape(14.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = Brass, contentColor = Ink),
                    ) { Text("حفظ الملف (.p12)", fontSize = 16.sp) }
                    Text(
                        "احفظ نسخة من الملف وكلمة السر. إذا ضاعوا ما تقدر تحدّث التطبيق على المتجر.",
                        fontSize = 13.sp, color = Ink.copy(alpha = 0.7f),
                    )
                }
            }
        }
    }
}

@Composable
private fun Section(title: String, content: @Composable ColumnScope.() -> Unit) {
    Column(
        Modifier.fillMaxWidth().background(Color.White, RoundedCornerShape(18.dp)).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Text(title, fontWeight = FontWeight.Bold, fontSize = 17.sp, color = Teal)
        content()
    }
}

@Composable
private fun Field(
    label: String, value: String, password: Boolean = false, number: Boolean = false, onChange: (String) -> Unit,
) {
    OutlinedTextField(
        value = value, onValueChange = onChange, label = { Text(label) },
        singleLine = true, modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(12.dp),
        visualTransformation = if (password) PasswordVisualTransformation() else androidx.compose.ui.text.input.VisualTransformation.None,
        keyboardOptions = KeyboardOptions(keyboardType = if (number) KeyboardType.Number else if (password) KeyboardType.Password else KeyboardType.Text),
    )
}

@Composable
private fun Info(label: String, value: String) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(label, fontSize = 12.sp, color = Ink.copy(alpha = 0.6f))
        Text(value, fontSize = 14.sp, fontWeight = FontWeight.Medium, color = Ink)
    }
}