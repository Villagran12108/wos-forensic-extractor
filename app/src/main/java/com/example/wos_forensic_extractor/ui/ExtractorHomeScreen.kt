package com.example.wos_forensic_extractor.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Album
import androidx.compose.material.icons.outlined.CreateNewFolder
import androidx.compose.material.icons.outlined.DriveFileMove
import androidx.compose.material.icons.outlined.FolderCopy
import androidx.compose.material.icons.outlined.FolderOpen
import androidx.compose.material.icons.rounded.AccessibilityNew
import androidx.compose.material.icons.rounded.Album
import androidx.compose.material.icons.rounded.Audiotrack
import androidx.compose.material.icons.rounded.AutoFixHigh
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Code
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.MovieCreation
import androidx.compose.material.icons.rounded.RocketLaunch
import androidx.compose.material.icons.rounded.Terrain
import androidx.compose.material.icons.rounded.Texture
import androidx.compose.material.icons.rounded.Transform
import androidx.compose.material.icons.rounded.Translate
import androidx.compose.material.icons.rounded.Verified
import androidx.compose.material.icons.rounded.ViewInAr
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.wos_forensic_extractor.R
import com.example.wos_forensic_extractor.model.ActiveMode
import com.example.wos_forensic_extractor.model.ConversionCompletedInfo
import com.example.wos_forensic_extractor.model.ForensicCategories
import com.example.wos_forensic_extractor.model.ForensicUiState
import com.example.wos_forensic_extractor.ui.theme.CardBorderSubtle
import com.example.wos_forensic_extractor.ui.theme.ConsoleBackground
import com.example.wos_forensic_extractor.ui.theme.ConsoleBorder
import com.example.wos_forensic_extractor.ui.theme.ConsoleHeaderBg
import com.example.wos_forensic_extractor.ui.theme.ConsoleTextDefault
import com.example.wos_forensic_extractor.ui.theme.JetBrainsMonoFamily
import com.example.wos_forensic_extractor.ui.theme.StatusError
import com.example.wos_forensic_extractor.ui.theme.StatusSuccess
import com.example.wos_forensic_extractor.ui.theme.StatusSuccessBorder
import com.example.wos_forensic_extractor.ui.theme.StatusSuccessContainer
import com.example.wos_forensic_extractor.ui.theme.StatusWarning
import java.util.Locale
import kotlin.math.roundToInt

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ExtractorHomeScreen(
    state: ForensicUiState,
    snackbarHostState: SnackbarHostState,
    onPickIsoClick: () -> Unit,
    onPickOutputDirClick: () -> Unit,
    onStartExtractionClick: () -> Unit,
    onPickDumpDirClick: () -> Unit,
    onStartConversionClick: () -> Unit,
    onDismissDialog: () -> Unit
) {
    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        snackbarHost = { SnackbarHost(hostState = snackbarHostState) },
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = stringResource(R.string.app_name),
                        style = MaterialTheme.typography.titleLarge,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                    titleContentColor = MaterialTheme.colorScheme.onBackground
                ),
                actions = {
                    if (state.isRunning) {
                        CircularProgressIndicator(
                            modifier = Modifier
                                .padding(end = 16.dp)
                                .size(20.dp)
                                .testTag("running_indicator"),
                            strokeWidth = 2.4.dp,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                }
            )
        }
    ) { innerPadding ->
        BoxWithConstraints(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .navigationBarsPadding()
        ) {
            val isExpanded = maxWidth >= 840.dp

            if (isExpanded) {
                Row(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                    horizontalArrangement = Arrangement.spacedBy(14.dp)
                ) {
                    Column(
                        modifier = Modifier
                            .weight(0.46f)
                            .verticalScroll(rememberScrollState()),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        ExtractIsoCard(
                            state = state,
                            onPickIsoClick = onPickIsoClick,
                            onPickOutputDirClick = onPickOutputDirClick,
                            onStartExtractionClick = onStartExtractionClick
                        )
                        PortConvertCard(
                            state = state,
                            onPickDumpDirClick = onPickDumpDirClick,
                            onStartConversionClick = onStartConversionClick
                        )
                        ConversionReadyBanner(state = state)
                    }

                    Column(
                        modifier = Modifier
                            .weight(0.54f)
                            .fillMaxSize(),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        ProgressCard(state = state)
                        CategoryCountersRow(categoryCounts = state.categoryCounts)
                        ForensicConsoleCard(
                            logs = state.logs,
                            modifier = Modifier
                                .fillMaxWidth()
                                .weight(1f)
                        )
                    }
                }
            } else {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .verticalScroll(rememberScrollState())
                        .padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    ExtractIsoCard(
                        state = state,
                        onPickIsoClick = onPickIsoClick,
                        onPickOutputDirClick = onPickOutputDirClick,
                        onStartExtractionClick = onStartExtractionClick
                    )

                    PortConvertCard(
                        state = state,
                        onPickDumpDirClick = onPickDumpDirClick,
                        onStartConversionClick = onStartConversionClick
                    )

                    ConversionReadyBanner(state = state)

                    ProgressCard(state = state)

                    CategoryCountersRow(categoryCounts = state.categoryCounts)

                    ForensicConsoleCard(
                        logs = state.logs,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(270.dp)
                    )
                }
            }
        }
    }

    val dialogInfo = state.completionDialog
    if (dialogInfo != null) {
        ConversionCompletedDialog(
            info = dialogInfo,
            onDismiss = onDismissDialog
        )
    }
}

@Composable
private fun ExtractIsoCard(
    state: ForensicUiState,
    onPickIsoClick: () -> Unit,
    onPickOutputDirClick: () -> Unit,
    onStartExtractionClick: () -> Unit
) {
    Card(
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        border = BorderStroke(1.dp, CardBorderSubtle)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Rounded.Album,
                    contentDescription = stringResource(R.string.card_extract_title),
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = stringResource(R.string.card_extract_title),
                    style = MaterialTheme.typography.titleSmall
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                FilledTonalButton(
                    onClick = onPickIsoClick,
                    enabled = !state.isRunning,
                    modifier = Modifier
                        .weight(1f)
                        .height(48.dp)
                        .testTag("pick_iso_button"),
                    contentPadding = PaddingValues(horizontal = 10.dp)
                ) {
                    Icon(
                        imageVector = Icons.Outlined.Album,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = stringResource(R.string.btn_pick_iso),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        style = MaterialTheme.typography.labelMedium
                    )
                }

                FilledTonalButton(
                    onClick = onPickOutputDirClick,
                    enabled = !state.isRunning,
                    modifier = Modifier
                        .weight(1f)
                        .height(48.dp)
                        .testTag("pick_output_dir_button"),
                    contentPadding = PaddingValues(horizontal = 10.dp)
                ) {
                    Icon(
                        imageVector = Icons.Outlined.FolderOpen,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = stringResource(R.string.btn_pick_output),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        style = MaterialTheme.typography.labelMedium
                    )
                }
            }

            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                val isoText = if (state.selectedIsoName != null && state.selectedIsoSizeGb != null) {
                    String.format(Locale.US, "%s (%.2f GB)", state.selectedIsoName, state.selectedIsoSizeGb)
                } else {
                    stringResource(R.string.none_selected)
                }
                InfoRow(
                    icon = Icons.Outlined.Album,
                    label = stringResource(R.string.label_iso),
                    value = isoText
                )
                InfoRow(
                    icon = Icons.Outlined.DriveFileMove,
                    label = stringResource(R.string.label_output),
                    value = state.selectedOutputDirDisplay ?: stringResource(R.string.none_selected)
                )
            }

            Button(
                onClick = onStartExtractionClick,
                enabled = !state.isRunning,
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.primary,
                    contentColor = MaterialTheme.colorScheme.onPrimary
                ),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp)
                    .testTag("start_extract_button")
            ) {
                Icon(
                    imageVector = Icons.Rounded.RocketLaunch,
                    contentDescription = null,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = if (state.isRunning && state.activeMode == ActiveMode.EXTRACT) {
                        stringResource(R.string.btn_extracting)
                    } else {
                        stringResource(R.string.btn_start_extract)
                    },
                    style = MaterialTheme.typography.labelLarge
                )
            }
        }
    }
}

@Composable
private fun PortConvertCard(
    state: ForensicUiState,
    onPickDumpDirClick: () -> Unit,
    onStartConversionClick: () -> Unit
) {
    Card(
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        border = BorderStroke(1.dp, CardBorderSubtle)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Rounded.Transform,
                    contentDescription = stringResource(R.string.card_convert_title),
                    tint = MaterialTheme.colorScheme.tertiary,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = stringResource(R.string.card_convert_title),
                    style = MaterialTheme.typography.titleSmall
                )
            }

            FilledTonalButton(
                onClick = onPickDumpDirClick,
                enabled = !state.isRunning,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp)
                    .testTag("pick_dump_dir_button")
            ) {
                Icon(
                    imageVector = Icons.Outlined.CreateNewFolder,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = stringResource(R.string.btn_pick_dump),
                    style = MaterialTheme.typography.labelMedium
                )
            }

            InfoRow(
                icon = Icons.Outlined.FolderCopy,
                label = stringResource(R.string.label_origin),
                value = state.selectedDumpDirDisplay ?: stringResource(R.string.origin_auto_hint)
            )

            Button(
                onClick = onStartConversionClick,
                enabled = !state.isRunning && !state.selectedDumpDirUri.isNullOrBlank(),
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.tertiaryContainer,
                    contentColor = MaterialTheme.colorScheme.onTertiaryContainer
                ),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp)
                    .testTag("start_convert_button")
            ) {
                Icon(
                    imageVector = Icons.Rounded.AutoFixHigh,
                    contentDescription = null,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = if (state.isRunning && state.activeMode == ActiveMode.CONVERT) {
                        stringResource(R.string.btn_converting)
                    } else {
                        stringResource(R.string.btn_start_convert)
                    },
                    style = MaterialTheme.typography.labelLarge
                )
            }
        }
    }
}

@Composable
private fun ConversionReadyBanner(state: ForensicUiState) {
    val bannerPath = state.convertedOutputDirBanner
    AnimatedVisibility(visible = bannerPath != null) {
        if (bannerPath != null) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .background(StatusSuccessContainer)
                    .border(1.dp, StatusSuccessBorder, RoundedCornerShape(12.dp))
                    .padding(12.dp)
                    .testTag("conversion_ready_banner")
            ) {
                Row(verticalAlignment = Alignment.Top) {
                    Icon(
                        imageVector = Icons.Rounded.Verified,
                        contentDescription = null,
                        tint = StatusSuccess,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(10.dp))
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(
                            text = "Conversión lista: ${state.convertedBannerTotal} convertidos (${state.convertedBannerSkipped} conservados en original)",
                            color = StatusSuccess,
                            fontWeight = FontWeight.Bold,
                            fontSize = 12.5.sp
                        )
                        SelectionContainer {
                            Text(
                                text = bannerPath,
                                fontFamily = JetBrainsMonoFamily,
                                fontSize = 11.5.sp,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ProgressCard(state: ForensicUiState) {
    val percent = (state.globalProgress * 100f).roundToInt()
    Card(
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        border = BorderStroke(1.dp, CardBorderSubtle)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = state.currentStageLabel.ifBlank { stringResource(R.string.stage_ready) },
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 13.sp,
                    modifier = Modifier.weight(1f)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "$percent%",
                    fontWeight = FontWeight.ExtraBold,
                    fontSize = 14.sp,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.testTag("progress_percent_text")
                )
            }

            LinearProgressIndicator(
                progress = { state.globalProgress.coerceIn(0f, 1f) },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(10.dp)
                    .clip(RoundedCornerShape(8.dp))
                    .testTag("global_progress_bar"),
                color = MaterialTheme.colorScheme.primary,
                trackColor = MaterialTheme.colorScheme.surfaceVariant
            )

            if (state.classifiedTotal > 0 || state.manifestResultPath != null) {
                Text(
                    text = if (state.manifestResultPath != null) {
                        "Manifiesto: ${state.manifestResultPath}"
                    } else {
                        "Progreso de archivos: ${state.classifiedProcessed} / ${state.classifiedTotal}"
                    },
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    fontSize = 11.5.sp,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.72f)
                )

                if (state.activeMode == ActiveMode.NONE &&
                    (state.ddsReconstructedCount > 0 || state.audioConverted48kHzCount > 0)
                ) {
                    Text(
                        text = "DDS reconstruidos: ${state.ddsReconstructedCount}  |  WAV 48kHz: ${state.audioConverted48kHzCount}",
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        fontSize = 11.sp,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.65f)
                    )
                }
            }
        }
    }
}

@Composable
private fun CategoryCountersRow(categoryCounts: Map<String, Int>) {
    LazyRow(
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        modifier = Modifier
            .fillMaxWidth()
            .testTag("category_counters_row")
    ) {
        items(ForensicCategories.ALL_CATEGORIES) { category ->
            CategoryCounterCard(
                category = category,
                count = categoryCounts[category] ?: 0
            )
        }
    }
}

@Composable
private fun CategoryCounterCard(category: String, count: Int) {
    val indexBadge = category.take(2)
    val shortTitle = category.drop(3).replace('_', ' ')
    val borderColor = if (count > 0) {
        MaterialTheme.colorScheme.primary.copy(alpha = 0.55f)
    } else {
        CardBorderSubtle
    }

    Surface(
        shape = RoundedCornerShape(14.dp),
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, borderColor),
        modifier = Modifier
            .width(146.dp)
            .height(114.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(10.dp),
            verticalArrangement = Arrangement.SpaceBetween
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.18f))
                        .padding(horizontal = 6.dp, vertical = 2.dp)
                ) {
                    Text(
                        text = indexBadge,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.ExtraBold,
                        color = MaterialTheme.colorScheme.primary
                    )
                }
                Icon(
                    imageVector = iconForCategory(category),
                    contentDescription = shortTitle,
                    tint = Color.White.copy(alpha = 0.72f),
                    modifier = Modifier.size(18.dp)
                )
            }

            Text(
                text = count.toString(),
                fontSize = 22.sp,
                fontWeight = FontWeight.ExtraBold,
                color = MaterialTheme.colorScheme.onSurface
            )

            Text(
                text = shortTitle,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
                fontSize = 11.sp,
                lineHeight = 13.sp,
                color = Color.White.copy(alpha = 0.75f)
            )
        }
    }
}

@Composable
private fun ForensicConsoleCard(
    logs: List<String>,
    modifier: Modifier = Modifier
) {
    val listState = rememberLazyListState()
    LaunchedEffect(logs.size) {
        if (logs.isNotEmpty()) {
            listState.scrollToItem(logs.size - 1)
        }
    }

    Column(
        modifier = modifier
            .clip(RoundedCornerShape(12.dp))
            .background(ConsoleBackground)
            .border(1.dp, ConsoleBorder, RoundedCornerShape(12.dp))
            .testTag("forensic_console")
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(ConsoleHeaderBg)
                .padding(horizontal = 12.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = stringResource(R.string.console_title),
                fontSize = 11.5.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = 0.8.sp,
                color = MaterialTheme.colorScheme.onSurface
            )
            Text(
                text = "${logs.size} líneas",
                fontSize = 11.sp,
                color = Color.White.copy(alpha = 0.55f)
            )
        }

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(1.dp)
                .background(CardBorderSubtle)
        )

        LazyColumn(
            state = listState,
            contentPadding = PaddingValues(10.dp),
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
        ) {
            items(logs) { line ->
                val lineColor = when {
                    line.contains("[ERROR]") || line.contains("[FATAL]") || line.contains("-ERR]") -> StatusError
                    line.contains("[WARN]") || line.contains("[FFMPEG-SKIP]") || line.contains("[CONV:SKIP]") -> StatusWarning
                    line.contains("[FIN]") || line.contains("[CONV:FIN]") -> StatusSuccess
                    else -> ConsoleTextDefault
                }
                Text(
                    text = line,
                    fontFamily = JetBrainsMonoFamily,
                    fontSize = 11.5.sp,
                    lineHeight = 16.sp,
                    color = lineColor
                )
            }
        }
    }
}

@Composable
private fun InfoRow(
    icon: ImageVector,
    label: String,
    value: String
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = Color.White.copy(alpha = 0.7f),
            modifier = Modifier.size(16.dp)
        )
        Spacer(modifier = Modifier.width(6.dp))
        Text(
            text = label,
            fontSize = 12.5.sp,
            fontWeight = FontWeight.Bold
        )
        Spacer(modifier = Modifier.width(6.dp))
        Text(
            text = value,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            fontSize = 12.5.sp,
            color = Color.White.copy(alpha = 0.82f),
            modifier = Modifier.weight(1f)
        )
    }
}

@Composable
private fun ConversionCompletedDialog(
    info: ConversionCompletedInfo,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Rounded.CheckCircle,
                    contentDescription = null,
                    tint = StatusSuccess
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = stringResource(R.string.dialog_convert_done_title),
                    style = MaterialTheme.typography.titleMedium
                )
            }
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(text = stringResource(R.string.dialog_analyzed, info.totalAnalyzed))
                Text(text = stringResource(R.string.dialog_converted, info.totalConverted))
                Text(text = stringResource(R.string.dialog_skipped, info.totalSkipped))
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = stringResource(R.string.dialog_folder_label),
                    fontWeight = FontWeight.Bold,
                    fontSize = 12.5.sp
                )
                SelectionContainer {
                    Text(
                        text = info.outputDir,
                        fontFamily = JetBrainsMonoFamily,
                        fontSize = 11.5.sp,
                        color = StatusSuccess
                    )
                }
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = stringResource(R.string.dialog_manifest_label),
                    fontWeight = FontWeight.Bold,
                    fontSize = 12.5.sp
                )
                SelectionContainer {
                    Text(
                        text = info.manifestPath,
                        fontFamily = JetBrainsMonoFamily,
                        fontSize = 11.sp
                    )
                }
            }
        },
        confirmButton = {
            Button(
                onClick = onDismiss,
                modifier = Modifier.testTag("dialog_confirm_button")
            ) {
                Text(text = stringResource(R.string.dialog_ok))
            }
        }
    )
}

private fun iconForCategory(category: String): ImageVector = when (category) {
    ForensicCategories.CAT_01_AUDIO -> Icons.Rounded.Audiotrack
    ForensicCategories.CAT_02_VIDEOS -> Icons.Rounded.MovieCreation
    ForensicCategories.CAT_03_TEXTURES -> Icons.Rounded.Texture
    ForensicCategories.CAT_04_MODELS -> Icons.Rounded.ViewInAr
    ForensicCategories.CAT_05_SKELETONS -> Icons.Rounded.AccessibilityNew
    ForensicCategories.CAT_06_PHYSICS -> Icons.Rounded.Terrain
    ForensicCategories.CAT_07_ENTITIES -> Icons.Rounded.Code
    ForensicCategories.CAT_08_TEXTS -> Icons.Rounded.Translate
    else -> Icons.Rounded.Memory
}
