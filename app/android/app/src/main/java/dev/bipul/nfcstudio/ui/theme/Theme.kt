package dev.bipul.nfcstudio.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

private val Light = lightColorScheme(
    primary = Color(0xFF2856D8),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFDCE2FF),
    onPrimaryContainer = Color(0xFF001550),
    secondary = Color(0xFF585E72),
    secondaryContainer = Color(0xFFDDE1F9),
    tertiary = Color(0xFF7A3FB0),
    tertiaryContainer = Color(0xFFF1DBFF),
    background = Color(0xFFFBF8FF),
    surface = Color(0xFFFBF8FF),
    surfaceVariant = Color(0xFFE2E1EC),
)

private val Dark = darkColorScheme(
    primary = Color(0xFFB6C4FF),
    onPrimary = Color(0xFF00277E),
    primaryContainer = Color(0xFF0B3CB5),
    onPrimaryContainer = Color(0xFFDCE2FF),
    secondary = Color(0xFFC1C5DD),
    secondaryContainer = Color(0xFF41465A),
    tertiary = Color(0xFFDFB7FF),
    tertiaryContainer = Color(0xFF5F2496),
    background = Color(0xFF121318),
    surface = Color(0xFF121318),
)

private val AppTypography = Typography().run {
    copy(
        headlineSmall = headlineSmall.copy(fontWeight = FontWeight.SemiBold),
        titleLarge = titleLarge.copy(fontWeight = FontWeight.SemiBold),
        titleMedium = titleMedium.copy(fontWeight = FontWeight.SemiBold, fontSize = 17.sp),
    )
}

@Composable
fun NfcStudioTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val colors = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val ctx = LocalContext.current
            if (dark) dynamicDarkColorScheme(ctx) else dynamicLightColorScheme(ctx)
        }
        dark -> Dark
        else -> Light
    }
    MaterialTheme(colorScheme = colors, typography = AppTypography, content = content)
}
