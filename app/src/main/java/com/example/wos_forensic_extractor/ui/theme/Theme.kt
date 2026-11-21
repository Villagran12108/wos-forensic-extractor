package com.example.wos_forensic_extractor.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

private val ForensicDarkColorScheme = darkColorScheme(
    primary = CrimsonPrimary,
    onPrimary = Color.White,
    primaryContainer = CrimsonPrimaryContainer,
    onPrimaryContainer = CrimsonOnPrimaryContainer,
    secondary = Color(0xFF90A4AE),
    onSecondary = Color(0xFF101418),
    secondaryContainer = CardSurfaceElevated,
    onSecondaryContainer = Color(0xFFE2E8F0),
    tertiary = TertiaryAccent,
    onTertiary = Color(0xFF00213A),
    tertiaryContainer = TertiaryContainerBg,
    onTertiaryContainer = TertiaryOnContainer,
    background = ObsidianBackground,
    onBackground = Color(0xFFECEFF4),
    surface = CardSurface,
    onSurface = Color(0xFFECEFF4),
    surfaceVariant = CardSurfaceElevated,
    onSurfaceVariant = Color(0xFFB0BAC5),
    outline = CardBorderSubtle,
    error = StatusError,
    onError = Color(0xFF280000)
)

val AppShapes = Shapes(
    small = RoundedCornerShape(8.dp),
    medium = RoundedCornerShape(14.dp),
    large = RoundedCornerShape(18.dp)
)

@Composable
fun WoSForensicExtractorTheme(
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = ForensicDarkColorScheme,
        typography = AppTypography,
        shapes = AppShapes,
        content = content
    )
}
