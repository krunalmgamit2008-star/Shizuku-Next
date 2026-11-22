package moe.shizuku.manager.ui.component

import androidx.compose.ui.graphics.Color
import kotlin.math.abs

/** Vibrant per-icon colours, the way a launcher tints its glyphs. */
val IconPalette = listOf(
    Color(0xFF0A84FF),
    Color(0xFF30D158),
    Color(0xFFFF9F0A),
    Color(0xFFFF375F),
    Color(0xFFBF5AF2),
    Color(0xFF64D2FF),
    Color(0xFFFFD60A),
    Color(0xFF5E5CE6)
)

/** The colour a given icon name maps to. */
fun iconPaletteColor(name: String): Color = IconPalette[abs(name.hashCode()) % IconPalette.size]
