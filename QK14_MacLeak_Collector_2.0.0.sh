#!/bin/bash
# QK14 MacLeak Collector
# Live-response artifact acquisition and automated timeline analysis for macOS data-leak investigations.
# Designed for macOS Bash 3.2+ and native Apple utilities.
# Run only with proper authorization.

set -o pipefail
umask 077

VERSION="2.0.0"
LOG_DAYS=7
RECENT_DAYS=30
INCLUDE_COMMUNICATIONS=0
HASH_RECENT_FILES=0
DEEP_COLLECTION=0
AUTO_ANALYZE=1
DEST_PARENT=""
CASE_ID=""
START_UTC="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
START_EPOCH="$(date -u '+%s')"
START_STAMP="$(date -u '+%Y%m%dT%H%M%SZ')"

usage() {
  cat <<USAGE
Uso:
  sudo ./qk14_macleak_collector.sh [opciones]

Opciones:
  -d, --destination RUTA       Carpeta padre donde guardar la adquisición
  -c, --case ID                Identificador del procedimiento
  -l, --log-days N             Días de Unified Logs (por defecto: 7)
  -r, --recent-days N          Días para inventario de ficheros recientes (30)
      --include-communications Incluye bases de mensajes y perfiles de correo
      --hash-recent-files      Calcula SHA-256 de ficheros recientes inventariados
      --deep                    Intenta copiar FSEvents y Spotlight (puede ocupar mucho)
      --no-analysis             No genera timeline ni informe HTML automático
  -h, --help                   Muestra esta ayuda

Ejemplo:
  sudo ./qk14_macleak_collector.sh -d /Volumes/EVIDENCIA -c PER-2026-001 -l 14
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    -d|--destination)
      [ "$#" -ge 2 ] || { echo "Falta la ruta de destino" >&2; exit 2; }
      DEST_PARENT="$2"; shift 2 ;;
    -c|--case)
      [ "$#" -ge 2 ] || { echo "Falta el identificador" >&2; exit 2; }
      CASE_ID="$2"; shift 2 ;;
    -l|--log-days)
      [ "$#" -ge 2 ] || { echo "Falta el número de días" >&2; exit 2; }
      LOG_DAYS="$2"; shift 2 ;;
    -r|--recent-days)
      [ "$#" -ge 2 ] || { echo "Falta el número de días" >&2; exit 2; }
      RECENT_DAYS="$2"; shift 2 ;;
    --include-communications)
      INCLUDE_COMMUNICATIONS=1; shift ;;
    --hash-recent-files)
      HASH_RECENT_FILES=1; shift ;;
    --deep)
      DEEP_COLLECTION=1; shift ;;
    --no-analysis)
      AUTO_ANALYZE=0; shift ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "Opción desconocida: $1" >&2
      usage
      exit 2 ;;
  esac
done

case "$LOG_DAYS" in *[!0-9]*|'') echo "--log-days debe ser un entero" >&2; exit 2;; esac
case "$RECENT_DAYS" in *[!0-9]*|'') echo "--recent-days debe ser un entero" >&2; exit 2;; esac

if [ "$(uname -s 2>/dev/null)" != "Darwin" ]; then
  echo "ERROR: este colector está diseñado exclusivamente para macOS." >&2
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: ejecútalo con sudo para maximizar la adquisición:" >&2
  echo "  sudo $0" >&2
  exit 1
fi

cat <<'BANNER'
============================================================
 QK14 MacLeak Collector 2 - adquisición y análisis macOS
============================================================
Utilícese únicamente con autorización y documentando que una
recogida en vivo modifica inevitablemente algunos artefactos.
BANNER

if [ -z "$DEST_PARENT" ]; then
  printf "Carpeta de destino (ej. /Volumes/EVIDENCIA): "
  IFS= read -r DEST_PARENT
fi

if [ -z "$CASE_ID" ]; then
  printf "Identificador del procedimiento [MACLEAK-%s]: " "$START_STAMP"
  IFS= read -r CASE_ID
  [ -n "$CASE_ID" ] || CASE_ID="MACLEAK-$START_STAMP"
fi

[ -n "$DEST_PARENT" ] || { echo "Destino vacío" >&2; exit 1; }
mkdir -p "$DEST_PARENT" 2>/dev/null || { echo "No se puede crear/acceder al destino" >&2; exit 1; }
DEST_PARENT="$(cd "$DEST_PARENT" 2>/dev/null && pwd -P)" || exit 1

SAFE_CASE_ID="$(printf '%s' "$CASE_ID" | tr -cs 'A-Za-z0-9._-' '_')"
CASE_DIR="$DEST_PARENT/QK14_MacLeak_${SAFE_CASE_ID}_${START_STAMP}"

if [ -e "$CASE_DIR" ]; then
  echo "ERROR: ya existe $CASE_DIR" >&2
  exit 1
fi

mkdir -p \
  "$CASE_DIR/00_case" \
  "$CASE_DIR/01_system" \
  "$CASE_DIR/02_live" \
  "$CASE_DIR/03_network" \
  "$CASE_DIR/04_persistence" \
  "$CASE_DIR/05_unified_logs" \
  "$CASE_DIR/06_recent_inventory" \
  "$CASE_DIR/07_artifacts/filesystem" \
  "$CASE_DIR/08_reports" \
  "$CASE_DIR/09_manifests" \
  "$CASE_DIR/10_collector"

CASE_META="$CASE_DIR/00_case/case_info.txt"
ACQ_LOG="$CASE_DIR/00_case/acquisition.log"
ERROR_LOG="$CASE_DIR/00_case/errors.log"
FS_DIR="$CASE_DIR/07_artifacts/filesystem"
MANIFEST_DIR="$CASE_DIR/09_manifests"
RECENT_TSV="$CASE_DIR/06_recent_inventory/recent_files.tsv"

: > "$ACQ_LOG"
: > "$ERROR_LOG"

now_utc() {
  date -u '+%Y-%m-%dT%H:%M:%SZ'
}

log_event() {
  printf '%s\t%s\n' "$(now_utc)" "$*" >> "$ACQ_LOG"
}

record_error() {
  printf '%s\t%s\n' "$(now_utc)" "$*" >> "$ERROR_LOG"
  log_event "ERROR: $*"
}

on_interrupt() {
  log_event "ADQUISICION_INTERRUMPIDA señal recibida"
  echo "Adquisición interrumpida. Evidencia parcial: $CASE_DIR" >&2
  exit 130
}
trap on_interrupt INT TERM HUP

run_cmd() {
  label="$1"
  outfile="$2"
  shift 2
  mkdir -p "$(dirname "$outfile")"
  log_event "CMD_START [$label] $*"
  "$@" > "$outfile" 2>&1
  rc=$?
  if [ "$rc" -eq 0 ]; then
    log_event "CMD_OK [$label] salida=${outfile#$CASE_DIR/}"
  else
    record_error "CMD_FAIL rc=$rc [$label] salida=${outfile#$CASE_DIR/}"
  fi
  return 0
}

run_shell() {
  label="$1"
  outfile="$2"
  shell_command="$3"
  mkdir -p "$(dirname "$outfile")"
  log_event "CMD_START [$label] $shell_command"
  /bin/bash -c "$shell_command" > "$outfile" 2>&1
  rc=$?
  if [ "$rc" -eq 0 ]; then
    log_event "CMD_OK [$label] salida=${outfile#$CASE_DIR/}"
  else
    record_error "CMD_FAIL rc=$rc [$label] salida=${outfile#$CASE_DIR/}"
  fi
  return 0
}

copy_path() {
  src="$1"
  category="${2:-artifact}"

  if [ ! -e "$src" ] && [ ! -L "$src" ]; then
    return 0
  fi

  rel="${src#/}"
  dst="$FS_DIR/$rel"
  mkdir -p "$(dirname "$dst")"
  log_event "COPY_START [$category] $src"

  /usr/bin/ditto --rsrc --extattr --acl "$src" "$dst" >> "$ERROR_LOG" 2>&1
  rc=$?
  if [ "$rc" -eq 0 ]; then
    log_event "COPY_OK [$category] $src -> ${dst#$CASE_DIR/}"
  else
    record_error "COPY_FAIL rc=$rc [$category] $src"
  fi
  return 0
}

copy_sqlite_bundle() {
  db="$1"
  category="${2:-sqlite}"
  copy_path "$db" "$category"
  copy_path "${db}-wal" "$category-sidecar"
  copy_path "${db}-shm" "$category-sidecar"
  copy_path "${db}-journal" "$category-sidecar"
}

copy_matching_files() {
  base="$1"
  maxdepth="$2"
  category="$3"
  shift 3
  [ -d "$base" ] || return 0

  # Remaining arguments are file names or shell patterns interpreted by find -name.
  expr=""
  for pattern in "$@"; do
    escaped_pattern="$(printf '%s' "$pattern" | sed "s/'/'\\\\''/g")"
    if [ -z "$expr" ]; then
      expr="-name '$escaped_pattern'"
    else
      expr="$expr -o -name '$escaped_pattern'"
    fi
  done
  [ -n "$expr" ] || return 0

  while IFS= read -r -d '' found; do
    copy_path "$found" "$category"
  done < <(/bin/bash -c "find \"\$1\" -maxdepth \"\$2\" -type f \\( $expr \\) -print0 2>/dev/null" _ "$base" "$maxdepth")
}

stat_time() {
  kind="$1"
  file="$2"
  /usr/bin/stat -f "%S${kind}" -t '%Y-%m-%dT%H:%M:%S%z' "$file" 2>/dev/null || printf ''
}

sanitize_tsv() {
  printf '%s' "$1" | tr '\t\r\n' '   '
}

inventory_recent_root() {
  user_name="$1"
  root_path="$2"
  [ -d "$root_path" ] || return 0

  log_event "INVENTORY_START user=$user_name root=$root_path days=$RECENT_DAYS hash=$HASH_RECENT_FILES"

  while IFS= read -r -d '' file; do
    size="$(/usr/bin/stat -f '%z' "$file" 2>/dev/null || printf '0')"
    birth="$(stat_time B "$file")"
    modified="$(stat_time m "$file")"
    changed="$(stat_time c "$file")"
    accessed="$(stat_time a "$file")"
    epochs="$(/usr/bin/stat -f '%B|%m|%c|%a' "$file" 2>/dev/null || printf '|||')"
    old_ifs="$IFS"; IFS='|' read -r birth_epoch modified_epoch changed_epoch accessed_epoch <<EPOCHS
$epochs
EPOCHS
    IFS="$old_ifs"
    sha="NOT_CALCULATED"

    if [ "$HASH_RECENT_FILES" -eq 1 ]; then
      sha="$(/usr/bin/shasum -a 256 "$file" 2>>"$ERROR_LOG" | awk '{print $1}')"
      [ -n "$sha" ] || sha="HASH_ERROR"
    fi

    {
      sanitize_tsv "$sha"; printf '\t'
      sanitize_tsv "$size"; printf '\t'
      sanitize_tsv "$birth"; printf '\t'
      sanitize_tsv "$modified"; printf '\t'
      sanitize_tsv "$changed"; printf '\t'
      sanitize_tsv "$accessed"; printf '\t'
      sanitize_tsv "$user_name"; printf '\t'
      sanitize_tsv "$file"; printf '\t'
      sanitize_tsv "$birth_epoch"; printf '\t'
      sanitize_tsv "$modified_epoch"; printf '\t'
      sanitize_tsv "$changed_epoch"; printf '\t'
      sanitize_tsv "$accessed_epoch"; printf '\n'
    } >> "$RECENT_TSV"
  done < <(find "$root_path" -xdev -type f -mtime "-$RECENT_DAYS" -print0 2>>"$ERROR_LOG")

  log_event "INVENTORY_END user=$user_name root=$root_path"
}

collect_chromium_browser() {
  home="$1"
  browser_name="$2"
  base="$3"
  [ -d "$base" ] || return 0

  copy_matching_files "$base" 4 "browser-$browser_name" \
    "History" "History-wal" "History-shm" "History-journal" \
    "Preferences" "Secure Preferences" "Bookmarks" "Bookmarks.bak" \
    "Visited Links" "Current Session" "Current Tabs" "Last Session" "Last Tabs"
}

collect_user_artifacts() {
  home="$1"
  [ -d "$home" ] || return 0
  user_name="$(basename "$home")"
  [ "$user_name" = "Shared" ] && return 0

  log_event "USER_COLLECTION_START user=$user_name home=$home"

  # Shell and remote-transfer traces. Private SSH keys are intentionally excluded.
  copy_path "$home/.zsh_history" "shell-history"
  copy_path "$home/.bash_history" "shell-history"
  copy_path "$home/.zprofile" "shell-profile"
  copy_path "$home/.zshrc" "shell-profile"
  copy_path "$home/.bash_profile" "shell-profile"
  copy_path "$home/.bashrc" "shell-profile"
  copy_path "$home/.ssh/config" "ssh-metadata"
  copy_path "$home/.ssh/known_hosts" "ssh-metadata"
  copy_path "$home/.ssh/authorized_keys" "ssh-metadata"
  if [ -d "$home/.ssh" ]; then
    while IFS= read -r -d '' pubkey; do copy_path "$pubkey" "ssh-public-key"; done \
      < <(find "$home/.ssh" -maxdepth 1 -type f -name '*.pub' -print0 2>/dev/null)
  fi

  # Core macOS user artifacts.
  copy_sqlite_bundle "$home/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2" "quarantine"
  copy_sqlite_bundle "$home/Library/Application Support/Knowledge/knowledgeC.db" "knowledgec"
  copy_sqlite_bundle "$home/Library/Application Support/com.apple.TCC/TCC.db" "tcc-user"
  copy_path "$home/Library/Application Support/com.apple.sharedfilelist" "recent-items"
  copy_path "$home/Library/LaunchAgents" "launchagents-user"
  copy_path "$home/Library/Preferences/com.apple.recentitems.plist" "recent-items"

  # Safari.
  copy_sqlite_bundle "$home/Library/Safari/History.db" "browser-safari"
  copy_path "$home/Library/Safari/Downloads.plist" "browser-safari"
  copy_path "$home/Library/Safari/LastSession.plist" "browser-safari"
  copy_path "$home/Library/Safari/RecentlyClosedTabs.plist" "browser-safari"

  # Chromium-based browsers.
  collect_chromium_browser "$home" "chrome" "$home/Library/Application Support/Google/Chrome"
  collect_chromium_browser "$home" "edge" "$home/Library/Application Support/Microsoft Edge"
  collect_chromium_browser "$home" "brave" "$home/Library/Application Support/BraveSoftware/Brave-Browser"
  collect_chromium_browser "$home" "chromium" "$home/Library/Application Support/Chromium"
  collect_chromium_browser "$home" "arc" "$home/Library/Application Support/Arc/User Data"

  # Firefox.
  copy_matching_files "$home/Library/Application Support/Firefox/Profiles" 3 "browser-firefox" \
    "places.sqlite" "places.sqlite-wal" "places.sqlite-shm" "prefs.js" \
    "extensions.json" "sessionstore.jsonlz4" "sessionstore-backups"

  # Mail metadata only by default (Envelope Index and account configuration).
  copy_matching_files "$home/Library/Mail" 5 "mail-metadata" \
    "Envelope Index" "Envelope Index-wal" "Envelope Index-shm" "Accounts.plist"

  # Cloud-storage and file-provider logs/metadata.
  copy_path "$home/.dropbox/info.json" "cloud-dropbox"
  copy_matching_files "$home/Library/Application Support/Dropbox" 5 "cloud-dropbox" \
    "*.log" "*.db" "*.sqlite" "*.json" "*.plist"
  copy_matching_files "$home/Library/Application Support/Google/DriveFS" 6 "cloud-google-drive" \
    "*.log" "*.db" "*.sqlite" "*.json" "*.plist"
  copy_matching_files "$home/Library/Logs/Google Drive" 6 "cloud-google-drive" "*.log" "*.json"
  copy_matching_files "$home/Library/Application Support/OneDrive" 6 "cloud-onedrive" \
    "*.log" "*.db" "*.sqlite" "*.json" "*.plist"
  copy_matching_files "$home/Library/Logs/OneDrive" 6 "cloud-onedrive" "*.log" "*.json"
  copy_matching_files "$home/Library/Application Support/Box" 6 "cloud-box" \
    "*.log" "*.db" "*.sqlite" "*.json" "*.plist"
  copy_matching_files "$home/Library/Application Support/MEGAsync" 6 "cloud-mega" \
    "*.log" "*.db" "*.sqlite" "*.json" "*.plist"
  copy_matching_files "$home/Library/Application Support/Nextcloud" 6 "cloud-nextcloud" \
    "*.log" "*.db" "*.sqlite" "*.json" "*.plist"

  # Remote access and file-transfer client traces.
  copy_matching_files "$home/Library/Application Support/Cyberduck" 6 "transfer-cyberduck" \
    "*.log" "*.db" "*.sqlite" "*.json" "*.plist"
  copy_matching_files "$home/.config/filezilla" 5 "transfer-filezilla" \
    "*.xml" "*.log" "*.json"
  copy_matching_files "$home/Library/Application Support/FileZilla" 5 "transfer-filezilla" \
    "*.xml" "*.log" "*.json"
  copy_matching_files "$home/Library/Application Support/Transmit" 5 "transfer-transmit" \
    "*.log" "*.db" "*.sqlite" "*.json" "*.plist"
  copy_matching_files "$home/Library/Logs/TeamViewer" 6 "remote-teamviewer" "*.log" "*.txt"
  copy_matching_files "$home/Library/Logs/AnyDesk" 6 "remote-anydesk" "*.log" "*.trace" "*.txt"
  copy_matching_files "$home/Library/Application Support/AnyDesk" 5 "remote-anydesk" \
    "*.log" "*.conf" "*.trace" "*.txt"

  # Communications are opt-in because these databases can contain private content.
  if [ "$INCLUDE_COMMUNICATIONS" -eq 1 ]; then
    copy_sqlite_bundle "$home/Library/Messages/chat.db" "messages"
    copy_matching_files "$home/Library/Group Containers" 8 "communications" \
      "*.db" "*.sqlite" "*.sqlite3" "*.log"
    copy_matching_files "$home/Library/Application Support/Slack" 6 "communications-slack" \
      "*.db" "*.sqlite" "*.log" "*.json"
    copy_matching_files "$home/Library/Application Support/Telegram Desktop" 6 "communications-telegram" \
      "*.db" "*.sqlite" "*.log" "*.json"
    copy_matching_files "$home/Library/Application Support/WhatsApp" 6 "communications-whatsapp" \
      "*.db" "*.sqlite" "*.log" "*.json"
  fi

  # Metadata inventory of likely exfiltration staging areas.
  inventory_recent_root "$user_name" "$home/Desktop"
  inventory_recent_root "$user_name" "$home/Documents"
  inventory_recent_root "$user_name" "$home/Downloads"
  inventory_recent_root "$user_name" "$home/Library/CloudStorage"
  inventory_recent_root "$user_name" "$home/Library/Mobile Documents/com~apple~CloudDocs"

  log_event "USER_COLLECTION_END user=$user_name home=$home"
}

# -----------------------------------------------------------------------------
# Automatic analysis and unified activity timeline
# -----------------------------------------------------------------------------

analysis_log() {
  printf '%s\t%s\n' "$(now_utc)" "$*" >> "$ANALYSIS_LOG"
}

analysis_error() {
  printf '%s\t%s\n' "$(now_utc)" "$*" >> "$ANALYSIS_ERROR_LOG"
  analysis_log "ERROR: $*"
}

analysis_sanitize() {
  printf '%s' "$1" | tr '\t\r\n\037' '    '
}

analysis_truncate() {
  printf '%s' "$1" | /usr/bin/awk '{ if (length($0) > 1400) print substr($0,1,1400) "…"; else print $0 }'
}

redact_sensitive() {
  if command -v perl >/dev/null 2>&1; then
    printf '%s' "$1" | perl -pe 's{(password|passwd|token|secret|api[_-]?key|authorization)(\s*[:=]\s*)\S+}{$1$2[REDACTED]}ig; s{(https?://[^:/\s]+:)[^@/\s]+@}{$1[REDACTED]@}ig'
  else
    printf '%s' "$1"
  fi
}

iso_from_epoch() {
  epoch="$1"
  case "$epoch" in
    ''|*[!0-9-]*) printf '' ;;
    *) /bin/date -u -r "$epoch" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || printf '' ;;
  esac
}

source_relative() {
  src="$1"
  case "$src" in
    "$CASE_DIR"/*) printf '%s' "${src#$CASE_DIR/}" ;;
    *) printf '%s' "$src" ;;
  esac
}

source_sha256() {
  src="$1"
  [ -f "$src" ] || { printf ''; return 0; }
  /usr/bin/shasum -a 256 "$src" 2>>"$ANALYSIS_ERROR_LOG" | awk '{print $1}'
}

user_from_artifact_path() {
  p="$1"
  case "$p" in
    *"/Users/"*)
      rest="${p#*/Users/}"
      printf '%s' "${rest%%/*}"
      ;;
    *"/var/root/"*) printf 'root' ;;
    *) printf 'system' ;;
  esac
}

append_event() {
  epoch="$1"
  timestamp="$2"
  user_name="$3"
  category="$4"
  action="$5"
  application="$6"
  object="$7"
  details="$8"
  source_artifact="$9"
  confidence="${10}"
  risk="${11}"
  evidence_sha="${12}"

  case "$epoch" in
    ''|*[!0-9]*)
      {
        analysis_sanitize "$timestamp"; printf '\t'
        analysis_sanitize "$user_name"; printf '\t'
        analysis_sanitize "$category"; printf '\t'
        analysis_sanitize "$action"; printf '\t'
        analysis_sanitize "$application"; printf '\t'
        analysis_sanitize "$object"; printf '\t'
        analysis_sanitize "$(analysis_truncate "$details")"; printf '\t'
        analysis_sanitize "$source_artifact"; printf '\t'
        analysis_sanitize "$confidence"; printf '\t'
        analysis_sanitize "$risk"; printf '\t'
        analysis_sanitize "$evidence_sha"; printf '\n'
      } >> "$UNDATED_RAW"
      return 0
      ;;
  esac

  [ -n "$timestamp" ] || timestamp="$(iso_from_epoch "$epoch")"
  {
    printf '%020d\t' "$epoch"
    analysis_sanitize "$timestamp"; printf '\t'
    analysis_sanitize "$user_name"; printf '\t'
    analysis_sanitize "$category"; printf '\t'
    analysis_sanitize "$action"; printf '\t'
    analysis_sanitize "$application"; printf '\t'
    analysis_sanitize "$object"; printf '\t'
    analysis_sanitize "$(analysis_truncate "$details")"; printf '\t'
    analysis_sanitize "$source_artifact"; printf '\t'
    analysis_sanitize "$confidence"; printf '\t'
    analysis_sanitize "$risk"; printf '\t'
    analysis_sanitize "$evidence_sha"; printf '\n'
  } >> "$TIMELINE_RAW"
}

file_risk() {
  path_lc="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  size_bytes="${2:-0}"
  action_lc="$(printf '%s' "$3" | tr '[:upper:]' '[:lower:]')"
  risk="info"

  case "$path_lc" in
    *.zip|*.7z|*.rar|*.tar|*.tgz|*.tar.gz|*.dmg|*.iso)
      risk="medium"
      case "$size_bytes" in ''|*[!0-9]*) ;; *) [ "$size_bytes" -ge 52428800 ] && risk="high" ;; esac
      ;;
    *.csv|*.xlsx|*.xls|*.sql|*.db|*.sqlite|*.pst|*.ost|*.key|*.pem|*.p12|*.docx|*.pdf)
      risk="low"
      ;;
  esac

  case "$path_lc" in
    *"/library/cloudstorage/"*|*"/mobile documents/com~apple~clouddocs/"*)
      [ "$risk" = "info" ] && risk="medium"
      [ "$risk" = "low" ] && risk="medium"
      ;;
  esac

  case "$action_lc" in
    *access*) [ "$risk" = "high" ] || risk="info" ;;
  esac
  printf '%s' "$risk"
}

url_risk() {
  text_lc="$(printf '%s %s' "$1" "$2" | tr '[:upper:]' '[:lower:]')"
  case "$text_lc" in
    *wetransfer*|*transfer.sh*|*file.io*|*wormhole*|*send-anywhere*|*mega.nz*|*gofile.io*|*dropbox.com/s/*)
      printf 'high' ;;
    *drive.google.com*|*docs.google.com*|*dropbox*|*onedrive*|*sharepoint*|*icloud.com*|*box.com*|*nextcloud*)
      printf 'medium' ;;
    *) printf 'info' ;;
  esac
}

command_risk() {
  cmd_lc="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$cmd_lc" in
    *"scp "*|*"sftp "*|*"rsync "*|*"rclone "*|*"curl "*"--upload-file"*|*"curl "*" -t "*|*"ftp "*|*"nc "*|*"netcat "*)
      printf 'high' ;;
    *"zip "*|*"tar "*|*"7z "*|*"ditto "*" -c"*|*"openssl enc"*|*"base64 "*)
      printf 'medium' ;;
    *"rm -rf"*|*"srm "*|*"shred "*|*"history -c"*|*"unset histfile"*)
      printf 'high' ;;
    *) printf 'info' ;;
  esac
}

prepare_sqlite_copy() {
  src="$1"
  [ -f "$src" ] || return 1
  token="$(printf '%s' "$src" | /usr/bin/cksum | awk '{print $1}')"
  work_dir="$ANALYSIS_WORK/sqlite_$token"
  rm -rf "$work_dir" 2>/dev/null || true
  mkdir -p "$work_dir"
  base="$(basename "$src")"
  /bin/cp -p "$src" "$work_dir/$base" 2>>"$ANALYSIS_ERROR_LOG" || return 1
  for suffix in -wal -shm -journal; do
    [ -f "${src}${suffix}" ] && /bin/cp -p "${src}${suffix}" "$work_dir/${base}${suffix}" 2>>"$ANALYSIS_ERROR_LOG"
  done
  printf '%s' "$work_dir/$base"
}

sqlite_table_exists() {
  db="$1"; table="$2"
  /usr/bin/sqlite3 "$db" "SELECT 1 FROM sqlite_master WHERE type='table' AND name='$(printf '%s' "$table" | sed "s/'/''/g")' LIMIT 1;" 2>/dev/null | grep -q '^1$'
}

sqlite_columns() {
  db="$1"; table="$2"
  /usr/bin/sqlite3 "$db" "PRAGMA table_info(\"$table\");" 2>/dev/null | awk -F'|' '{print $2}'
}

has_column() {
  columns="$1"; wanted="$2"
  printf '%s\n' "$columns" | grep -Fxq "$wanted"
}

sqlite_query() {
  db="$1"; sql="$2"; outfile="$3"
  /usr/bin/sqlite3 -batch "$db" <<SQL > "$outfile" 2>>"$ANALYSIS_ERROR_LOG"
.timeout 10000
$sql
SQL
  return $?
}

parse_recent_inventory() {
  [ -f "$RECENT_TSV" ] || return 0
  analysis_log "Parsing recent file inventory"
  source_rel="$(source_relative "$RECENT_TSV")"
  while IFS=$'\t' read -r sha size birth modified changed accessed user_name path birth_epoch modified_epoch changed_epoch accessed_epoch; do
    [ "$sha" = "sha256" ] && continue
    [ -n "$path" ] || continue

    risk="$(file_risk "$path" "$size" "created")"
    [ -n "$birth_epoch" ] || birth_epoch=""
    append_event "$birth_epoch" "$birth" "$user_name" "Archivos" "Creación observada" "Sistema de archivos" "$path" "Tamaño: $size bytes. SHA-256 inventario: $sha" "$source_rel" "media" "$risk" "$sha"

    if [ -n "$modified_epoch" ] && [ "$modified_epoch" != "$birth_epoch" ]; then
      risk="$(file_risk "$path" "$size" "modified")"
      append_event "$modified_epoch" "$modified" "$user_name" "Archivos" "Modificación observada" "Sistema de archivos" "$path" "Tamaño: $size bytes. SHA-256 inventario: $sha" "$source_rel" "media" "$risk" "$sha"
    fi

    if [ -n "$changed_epoch" ] && [ "$changed_epoch" != "$modified_epoch" ] && [ "$changed_epoch" != "$birth_epoch" ]; then
      append_event "$changed_epoch" "$changed" "$user_name" "Archivos" "Cambio de metadatos" "Sistema de archivos" "$path" "Cambio de inode/metadatos; no equivale necesariamente a modificación de contenido." "$source_rel" "baja" "info" "$sha"
    fi

    if [ -n "$accessed_epoch" ] && [ "$accessed_epoch" != "$modified_epoch" ] && [ "$accessed_epoch" != "$birth_epoch" ]; then
      append_event "$accessed_epoch" "$accessed" "$user_name" "Archivos" "Último acceso registrado" "Sistema de archivos" "$path" "atime puede estar deshabilitado, diferido o alterado por la propia adquisición." "$source_rel" "baja" "info" "$sha"
    fi
  done < "$RECENT_TSV"
}

parse_chromium_history() {
  src="$1"; browser="$2"
  user_name="$(user_from_artifact_path "$src")"
  source_rel="$(source_relative "$src")"
  source_hash="$(source_sha256 "$src")"
  db="$(prepare_sqlite_copy "$src")" || { analysis_error "Cannot prepare SQLite: $source_rel"; return 0; }
  sqlite_table_exists "$db" visits || return 0
  sqlite_table_exists "$db" urls || return 0
  out="$ANALYSIS_WORK/chromium_visits_$(printf '%s' "$src" | cksum | awk '{print $1}').txt"
  sql="SELECT CAST((v.visit_time/1000000)-11644473600 AS INTEGER) || char(31) || strftime('%Y-%m-%dT%H:%M:%SZ',(v.visit_time/1000000)-11644473600,'unixepoch') || char(31) || replace(replace(COALESCE(u.url,''),char(9),' '),char(10),' ') || char(31) || replace(replace(COALESCE(u.title,''),char(9),' '),char(10),' ') || char(31) || COALESCE(v.transition,'') FROM visits v JOIN urls u ON u.id=v.url WHERE v.visit_time>0 ORDER BY v.visit_time;"
  sqlite_query "$db" "$sql" "$out" || { analysis_error "Browser query failed: $source_rel"; return 0; }
  while IFS=$'\037' read -r epoch ts url title transition; do
    [ -n "$epoch" ] || continue
    risk="$(url_risk "$url" "$title")"
    append_event "$epoch" "$ts" "$user_name" "Navegación" "Visita web" "$browser" "$url" "Título: $title. Transición: $transition" "$source_rel" "alta" "$risk" "$source_hash"
  done < "$out"

  if sqlite_table_exists "$db" downloads; then
    cols="$(sqlite_columns "$db" downloads)"
    time_col=""; target_col=""; state_col=""; bytes_col=""; url_expr="''"
    has_column "$cols" start_time && time_col="start_time"
    [ -n "$time_col" ] || { has_column "$cols" end_time && time_col="end_time"; }
    has_column "$cols" target_path && target_col="target_path"
    [ -n "$target_col" ] || { has_column "$cols" current_path && target_col="current_path"; }
    has_column "$cols" state && state_col="state"
    has_column "$cols" received_bytes && bytes_col="received_bytes"
    if sqlite_table_exists "$db" downloads_url_chains; then
      url_expr="COALESCE((SELECT duc.url FROM downloads_url_chains duc WHERE duc.id=d.id ORDER BY duc.chain_index LIMIT 1),'')"
    elif has_column "$cols" tab_url; then
      url_expr="COALESCE(d.tab_url,'')"
    elif has_column "$cols" referrer; then
      url_expr="COALESCE(d.referrer,'')"
    fi
    if [ -n "$time_col" ] && [ -n "$target_col" ]; then
      state_expr="''"; bytes_expr="''"
      [ -n "$state_col" ] && state_expr="COALESCE(d.$state_col,'')"
      [ -n "$bytes_col" ] && bytes_expr="COALESCE(d.$bytes_col,'')"
      out="$ANALYSIS_WORK/chromium_downloads_$(printf '%s' "$src" | cksum | awk '{print $1}').txt"
      sql="SELECT CAST((d.$time_col/1000000)-11644473600 AS INTEGER) || char(31) || strftime('%Y-%m-%dT%H:%M:%SZ',(d.$time_col/1000000)-11644473600,'unixepoch') || char(31) || replace(replace(COALESCE(d.$target_col,''),char(9),' '),char(10),' ') || char(31) || replace(replace($url_expr,char(9),' '),char(10),' ') || char(31) || $state_expr || char(31) || $bytes_expr FROM downloads d WHERE d.$time_col>0 ORDER BY d.$time_col;"
      if sqlite_query "$db" "$sql" "$out"; then
        while IFS=$'\037' read -r epoch ts target url state bytes; do
          [ -n "$epoch" ] || continue
          risk="$(file_risk "$target" "${bytes:-0}" "download")"
          append_event "$epoch" "$ts" "$user_name" "Descargas" "Descarga registrada" "$browser" "$target" "URL: $url. Estado: $state. Bytes recibidos: $bytes" "$source_rel" "alta" "$risk" "$source_hash"
        done < "$out"
      fi
    fi
  fi
}

parse_safari_history() {
  src="$1"
  user_name="$(user_from_artifact_path "$src")"
  source_rel="$(source_relative "$src")"
  source_hash="$(source_sha256 "$src")"
  db="$(prepare_sqlite_copy "$src")" || return 0
  sqlite_table_exists "$db" history_visits || return 0
  sqlite_table_exists "$db" history_items || return 0
  out="$ANALYSIS_WORK/safari_$(printf '%s' "$src" | cksum | awk '{print $1}').txt"
  sql="SELECT CAST(hv.visit_time+978307200 AS INTEGER) || char(31) || strftime('%Y-%m-%dT%H:%M:%SZ',hv.visit_time+978307200,'unixepoch') || char(31) || replace(replace(COALESCE(hi.url,''),char(9),' '),char(10),' ') || char(31) || replace(replace(COALESCE(hv.title,hi.title,''),char(9),' '),char(10),' ') FROM history_visits hv JOIN history_items hi ON hi.id=hv.history_item WHERE hv.visit_time IS NOT NULL ORDER BY hv.visit_time;"
  sqlite_query "$db" "$sql" "$out" || { analysis_error "Safari query failed: $source_rel"; return 0; }
  while IFS=$'\037' read -r epoch ts url title; do
    [ -n "$epoch" ] || continue
    risk="$(url_risk "$url" "$title")"
    append_event "$epoch" "$ts" "$user_name" "Navegación" "Visita web" "Safari" "$url" "Título: $title" "$source_rel" "alta" "$risk" "$source_hash"
  done < "$out"
}

parse_firefox_history() {
  src="$1"
  user_name="$(user_from_artifact_path "$src")"
  source_rel="$(source_relative "$src")"
  source_hash="$(source_sha256 "$src")"
  db="$(prepare_sqlite_copy "$src")" || return 0
  sqlite_table_exists "$db" moz_historyvisits || return 0
  sqlite_table_exists "$db" moz_places || return 0
  out="$ANALYSIS_WORK/firefox_$(printf '%s' "$src" | cksum | awk '{print $1}').txt"
  sql="SELECT CAST(h.visit_date/1000000 AS INTEGER) || char(31) || strftime('%Y-%m-%dT%H:%M:%SZ',h.visit_date/1000000,'unixepoch') || char(31) || replace(replace(COALESCE(p.url,''),char(9),' '),char(10),' ') || char(31) || replace(replace(COALESCE(p.title,''),char(9),' '),char(10),' ') || char(31) || COALESCE(h.visit_type,'') FROM moz_historyvisits h JOIN moz_places p ON p.id=h.place_id WHERE h.visit_date>0 ORDER BY h.visit_date;"
  sqlite_query "$db" "$sql" "$out" || { analysis_error "Firefox query failed: $source_rel"; return 0; }
  while IFS=$'\037' read -r epoch ts url title visit_type; do
    [ -n "$epoch" ] || continue
    risk="$(url_risk "$url" "$title")"
    append_event "$epoch" "$ts" "$user_name" "Navegación" "Visita web" "Firefox" "$url" "Título: $title. Tipo de visita: $visit_type" "$source_rel" "alta" "$risk" "$source_hash"
  done < "$out"
}

parse_quarantine_db() {
  src="$1"
  user_name="$(user_from_artifact_path "$src")"
  source_rel="$(source_relative "$src")"
  source_hash="$(source_sha256 "$src")"
  db="$(prepare_sqlite_copy "$src")" || return 0
  sqlite_table_exists "$db" LSQuarantineEvent || return 0
  cols="$(sqlite_columns "$db" LSQuarantineEvent)"
  has_column "$cols" LSQuarantineTimeStamp || return 0
  agent="''"; origin="''"; dataurl="''"; sender="''"
  has_column "$cols" LSQuarantineAgentName && agent="COALESCE(LSQuarantineAgentName,'')"
  has_column "$cols" LSQuarantineOriginURLString && origin="COALESCE(LSQuarantineOriginURLString,'')"
  has_column "$cols" LSQuarantineDataURLString && dataurl="COALESCE(LSQuarantineDataURLString,'')"
  has_column "$cols" LSQuarantineSenderName && sender="COALESCE(LSQuarantineSenderName,'')"
  out="$ANALYSIS_WORK/quarantine_$(printf '%s' "$src" | cksum | awk '{print $1}').txt"
  sql="SELECT CAST(LSQuarantineTimeStamp+978307200 AS INTEGER) || char(31) || strftime('%Y-%m-%dT%H:%M:%SZ',LSQuarantineTimeStamp+978307200,'unixepoch') || char(31) || replace(replace($agent,char(9),' '),char(10),' ') || char(31) || replace(replace($origin,char(9),' '),char(10),' ') || char(31) || replace(replace($dataurl,char(9),' '),char(10),' ') || char(31) || replace(replace($sender,char(9),' '),char(10),' ') FROM LSQuarantineEvent WHERE LSQuarantineTimeStamp IS NOT NULL ORDER BY LSQuarantineTimeStamp;"
  sqlite_query "$db" "$sql" "$out" || return 0
  while IFS=$'\037' read -r epoch ts agent_name origin_url data_url sender_name; do
    [ -n "$epoch" ] || continue
    risk="$(url_risk "$origin_url" "$data_url")"
    append_event "$epoch" "$ts" "$user_name" "Descargas" "Entrada en cuarentena" "$agent_name" "$data_url" "Origen: $origin_url. Remitente: $sender_name" "$source_rel" "alta" "$risk" "$source_hash"
  done < "$out"
}

parse_tcc_db() {
  src="$1"
  user_name="$(user_from_artifact_path "$src")"
  source_rel="$(source_relative "$src")"
  source_hash="$(source_sha256 "$src")"
  db="$(prepare_sqlite_copy "$src")" || return 0
  sqlite_table_exists "$db" access || return 0
  cols="$(sqlite_columns "$db" access)"
  has_column "$cols" service || return 0
  has_column "$cols" client || return 0
  has_column "$cols" last_modified || return 0
  auth="''"; prompt="''"; indirect="''"
  if has_column "$cols" auth_value; then auth="COALESCE(auth_value,'')"; elif has_column "$cols" allowed; then auth="COALESCE(allowed,'')"; fi
  has_column "$cols" prompt_count && prompt="COALESCE(prompt_count,'')"
  has_column "$cols" indirect_object_identifier && indirect="COALESCE(indirect_object_identifier,'')"
  out="$ANALYSIS_WORK/tcc_$(printf '%s' "$src" | cksum | awk '{print $1}').txt"
  sql="SELECT CAST(last_modified AS INTEGER) || char(31) || strftime('%Y-%m-%dT%H:%M:%SZ',last_modified,'unixepoch') || char(31) || replace(COALESCE(service,''),char(9),' ') || char(31) || replace(COALESCE(client,''),char(9),' ') || char(31) || $auth || char(31) || $prompt || char(31) || replace($indirect,char(9),' ') FROM access WHERE last_modified>0 ORDER BY last_modified;"
  sqlite_query "$db" "$sql" "$out" || return 0
  while IFS=$'\037' read -r epoch ts service client auth_value prompt_count indirect_object; do
    [ -n "$epoch" ] || continue
    risk="info"
    case "$(printf '%s' "$service" | tr '[:upper:]' '[:lower:]')" in
      *screen*|*camera*|*microphone*|*addressbook*|*photos*|*systempolicyallfiles*) risk="low" ;;
    esac
    append_event "$epoch" "$ts" "$user_name" "Permisos" "Cambio/registro TCC" "$client" "$service" "Valor de autorización: $auth_value. Solicitudes: $prompt_count. Objeto indirecto: $indirect_object" "$source_rel" "alta" "$risk" "$source_hash"
  done < "$out"
}

parse_knowledgec_db() {
  src="$1"
  user_name="$(user_from_artifact_path "$src")"
  source_rel="$(source_relative "$src")"
  source_hash="$(source_sha256 "$src")"
  db="$(prepare_sqlite_copy "$src")" || return 0
  sqlite_table_exists "$db" ZOBJECT || return 0
  cols="$(sqlite_columns "$db" ZOBJECT)"
  date_col=""; stream_expr="''"; value_expr="''"; bundle_expr="''"; duration_expr="''"
  for candidate in ZSTARTDATE ZCREATIONDATE ZENDDATE; do has_column "$cols" "$candidate" && { date_col="$candidate"; break; }; done
  [ -n "$date_col" ] || return 0
  for candidate in ZSTREAMNAME ZSTREAMIDENTIFIER; do has_column "$cols" "$candidate" && { stream_expr="COALESCE($candidate,'')"; break; }; done
  for candidate in ZVALUESTRING ZSTRING ZTITLE ZTEXT; do has_column "$cols" "$candidate" && { value_expr="COALESCE($candidate,'')"; break; }; done
  for candidate in ZBUNDLEID ZORIGINATINGBUNDLEID ZAPPLICATION; do has_column "$cols" "$candidate" && { bundle_expr="COALESCE($candidate,'')"; break; }; done
  has_column "$cols" ZDURATION && duration_expr="COALESCE(ZDURATION,'')"
  out="$ANALYSIS_WORK/knowledgec_$(printf '%s' "$src" | cksum | awk '{print $1}').txt"
  sql="SELECT CAST($date_col+978307200 AS INTEGER) || char(31) || strftime('%Y-%m-%dT%H:%M:%SZ',$date_col+978307200,'unixepoch') || char(31) || replace(replace($stream_expr,char(9),' '),char(10),' ') || char(31) || replace(replace($value_expr,char(9),' '),char(10),' ') || char(31) || replace(replace($bundle_expr,char(9),' '),char(10),' ') || char(31) || $duration_expr FROM ZOBJECT WHERE $date_col IS NOT NULL ORDER BY $date_col;"
  sqlite_query "$db" "$sql" "$out" || { analysis_error "KnowledgeC query failed: $source_rel"; return 0; }
  while IFS=$'\037' read -r epoch ts stream value bundle duration; do
    [ -n "$epoch" ] || continue
    risk="$(url_risk "$bundle" "$value")"
    append_event "$epoch" "$ts" "$user_name" "Actividad de usuario" "Evento KnowledgeC" "$bundle" "$stream" "Valor: $value. Duración: $duration" "$source_rel" "media" "$risk" "$source_hash"
  done < "$out"
}

parse_messages_db() {
  src="$1"
  user_name="$(user_from_artifact_path "$src")"
  source_rel="$(source_relative "$src")"
  source_hash="$(source_sha256 "$src")"
  db="$(prepare_sqlite_copy "$src")" || return 0
  sqlite_table_exists "$db" message || return 0
  cols="$(sqlite_columns "$db" message)"
  has_column "$cols" date || return 0
  handle_expr="''"
  if sqlite_table_exists "$db" handle && has_column "$cols" handle_id; then
    handle_expr="COALESCE((SELECT h.id FROM handle h WHERE h.ROWID=m.handle_id),'')"
  fi
  from_expr="''"; service_expr="''"; cache_expr="''"
  has_column "$cols" is_from_me && from_expr="COALESCE(m.is_from_me,'')"
  has_column "$cols" service && service_expr="COALESCE(m.service,'')"
  has_column "$cols" cache_has_attachments && cache_expr="COALESCE(m.cache_has_attachments,'')"
  out="$ANALYSIS_WORK/messages_$(printf '%s' "$src" | cksum | awk '{print $1}').txt"
  sql="SELECT CAST((CASE WHEN m.date>1000000000000 THEN m.date/1000000000 ELSE m.date END)+978307200 AS INTEGER) || char(31) || strftime('%Y-%m-%dT%H:%M:%SZ',(CASE WHEN m.date>1000000000000 THEN m.date/1000000000 ELSE m.date END)+978307200,'unixepoch') || char(31) || replace($handle_expr,char(9),' ') || char(31) || $from_expr || char(31) || replace($service_expr,char(9),' ') || char(31) || $cache_expr FROM message m WHERE m.date>0 ORDER BY m.date;"
  sqlite_query "$db" "$sql" "$out" || return 0
  while IFS=$'\037' read -r epoch ts handle_id is_from_me service has_attachment; do
    [ -n "$epoch" ] || continue
    action="Mensaje recibido"; risk="info"
    [ "$is_from_me" = "1" ] && { action="Mensaje enviado"; [ "$has_attachment" = "1" ] && risk="high" || risk="low"; }
    append_event "$epoch" "$ts" "$user_name" "Mensajería" "$action" "$service" "$handle_id" "Contiene adjunto: $has_attachment. No se incluye el cuerpo del mensaje." "$source_rel" "alta" "$risk" "$source_hash"
  done < "$out"

  if sqlite_table_exists "$db" attachment && sqlite_table_exists "$db" message_attachment_join; then
    acols="$(sqlite_columns "$db" attachment)"
    filename_expr="''"; transfer_expr="''"; bytes_expr="''"; created_col=""
    has_column "$acols" filename && filename_expr="COALESCE(a.filename,'')"
    has_column "$acols" transfer_name && transfer_expr="COALESCE(a.transfer_name,'')"
    has_column "$acols" total_bytes && bytes_expr="COALESCE(a.total_bytes,'')"
    for candidate in created_date start_date; do has_column "$acols" "$candidate" && { created_col="$candidate"; break; }; done
    if [ -n "$created_col" ]; then
      out="$ANALYSIS_WORK/message_attachments_$(printf '%s' "$src" | cksum | awk '{print $1}').txt"
      sql="SELECT CAST((CASE WHEN a.$created_col>1000000000000 THEN a.$created_col/1000000000 ELSE a.$created_col END)+978307200 AS INTEGER) || char(31) || strftime('%Y-%m-%dT%H:%M:%SZ',(CASE WHEN a.$created_col>1000000000000 THEN a.$created_col/1000000000 ELSE a.$created_col END)+978307200,'unixepoch') || char(31) || replace($filename_expr,char(9),' ') || char(31) || replace($transfer_expr,char(9),' ') || char(31) || $bytes_expr FROM attachment a WHERE a.$created_col>0 ORDER BY a.$created_col;"
      if sqlite_query "$db" "$sql" "$out"; then
        while IFS=$'\037' read -r epoch ts filename transfer_name total_bytes; do
          [ -n "$epoch" ] || continue
          risk="$(file_risk "$transfer_name" "${total_bytes:-0}" "attachment")"
          append_event "$epoch" "$ts" "$user_name" "Mensajería" "Adjunto registrado" "Messages" "$transfer_name" "Ruta: $filename. Tamaño: $total_bytes bytes." "$source_rel" "media" "$risk" "$source_hash"
        done < "$out"
      fi
    fi
  fi
}

parse_mail_envelope() {
  src="$1"
  user_name="$(user_from_artifact_path "$src")"
  source_rel="$(source_relative "$src")"
  source_hash="$(source_sha256 "$src")"
  db="$(prepare_sqlite_copy "$src")" || return 0
  sqlite_table_exists "$db" messages || return 0
  cols="$(sqlite_columns "$db" messages)"
  date_col=""
  for candidate in date_sent date_received date; do has_column "$cols" "$candidate" && { date_col="$candidate"; break; }; done
  [ -n "$date_col" ] || return 0

  subject_expr="''"; sender_expr="''"; mailbox_expr="''"; size_expr="''"
  if has_column "$cols" subject; then
    if sqlite_table_exists "$db" subjects && printf '%s\n' "$(sqlite_columns "$db" subjects)" | grep -Fxq subject; then
      subject_expr="COALESCE((SELECT s.subject FROM subjects s WHERE s.ROWID=m.subject),'')"
    else
      subject_expr="COALESCE(CAST(m.subject AS TEXT),'')"
    fi
  fi
  if has_column "$cols" sender; then
    if sqlite_table_exists "$db" addresses && printf '%s\n' "$(sqlite_columns "$db" addresses)" | grep -Fxq address; then
      sender_expr="COALESCE((SELECT a.address FROM addresses a WHERE a.ROWID=m.sender),'')"
    else
      sender_expr="COALESCE(CAST(m.sender AS TEXT),'')"
    fi
  fi
  if has_column "$cols" mailbox; then
    if sqlite_table_exists "$db" mailboxes; then
      mailbox_cols="$(sqlite_columns "$db" mailboxes)"
      if has_column "$mailbox_cols" url; then
        mailbox_expr="COALESCE((SELECT mb.url FROM mailboxes mb WHERE mb.ROWID=m.mailbox),'')"
      elif has_column "$mailbox_cols" path; then
        mailbox_expr="COALESCE((SELECT mb.path FROM mailboxes mb WHERE mb.ROWID=m.mailbox),'')"
      else
        mailbox_expr="COALESCE(CAST(m.mailbox AS TEXT),'')"
      fi
    else
      mailbox_expr="COALESCE(CAST(m.mailbox AS TEXT),'')"
    fi
  fi
  has_column "$cols" size && size_expr="COALESCE(m.size,'')"

  out="$ANALYSIS_WORK/mail_$(printf '%s' "$src" | cksum | awk '{print $1}').txt"
  epoch_expr="CAST(CASE WHEN m.$date_col>0 AND m.$date_col<1100000000 THEN m.$date_col+978307200 ELSE m.$date_col END AS INTEGER)"
  sql="SELECT $epoch_expr || char(31) || strftime('%Y-%m-%dT%H:%M:%SZ',$epoch_expr,'unixepoch') || char(31) || replace(replace($sender_expr,char(9),' '),char(10),' ') || char(31) || replace(replace($subject_expr,char(9),' '),char(10),' ') || char(31) || replace(replace($mailbox_expr,char(9),' '),char(10),' ') || char(31) || $size_expr FROM messages m WHERE m.$date_col>0 ORDER BY m.$date_col;"
  sqlite_query "$db" "$sql" "$out" || { analysis_error "Mail Envelope query failed: $source_rel"; return 0; }
  while IFS=$'\037' read -r epoch ts sender subject mailbox size; do
    [ -n "$epoch" ] || continue
    action="Correo indexado"; risk="info"
    mailbox_lc="$(printf '%s' "$mailbox" | tr '[:upper:]' '[:lower:]')"
    case "$mailbox_lc" in *sent*|*enviado*|*outbox*) action="Correo enviado/indexado"; risk="low" ;; esac
    case "$(printf '%s' "$subject" | tr '[:upper:]' '[:lower:]')" in *confidencial*|*password*|*credencial*|*clientes*|*base\ de\ datos*) [ "$action" = "Correo enviado/indexado" ] && risk="medium" ;; esac
    append_event "$epoch" "$ts" "$user_name" "Correo" "$action" "Apple Mail" "$subject" "Remitente: $sender. Buzón: $mailbox. Tamaño: $size bytes." "$source_rel" "media" "$risk" "$source_hash"
  done < "$out"
}

parse_spotlight_reports() {
  combined="$ANALYSIS_WORK/spotlight_paths.txt"
  : > "$combined"
  for report in "$CASE_DIR/08_reports/spotlight_archives.txt" "$CASE_DIR/08_reports/spotlight_wherefroms.txt"; do
    [ -f "$report" ] || continue
    grep '^/' "$report" 2>/dev/null >> "$combined"
  done
  [ -s "$combined" ] || return 0
  LC_ALL=C sort -u "$combined" -o "$combined"
  source_rel="08_reports/spotlight_archives.txt / spotlight_wherefroms.txt"
  while IFS= read -r path; do
    [ -f "$path" ] || continue
    size="$(/usr/bin/stat -f '%z' "$path" 2>/dev/null || printf '0')"
    birth_epoch="$(/usr/bin/stat -f '%B' "$path" 2>/dev/null || printf '')"
    modified_epoch="$(/usr/bin/stat -f '%m' "$path" 2>/dev/null || printf '')"
    birth="$(stat_time B "$path")"; modified="$(stat_time m "$path")"
    wherefrom="$(/usr/bin/mdls -raw -name kMDItemWhereFroms "$path" 2>/dev/null | tr '\r\n\t' '   ')"
    last_used_raw="$(/usr/bin/mdls -raw -name kMDItemLastUsedDate "$path" 2>/dev/null | tr -d '\n')"
    last_used_epoch=""
    case "$last_used_raw" in
      [0-9][0-9][0-9][0-9]-*)
        compact="$(printf '%s' "$last_used_raw" | sed -E 's/\.[0-9]+ //; s/ \+0000$/+0000/; s/ /T/1')"
        parse="$(printf '%s' "$compact" | sed -E 's/T/ /')"
        last_used_epoch="$(/bin/date -j -f '%Y-%m-%d %H:%M:%S%z' "$parse" '+%s' 2>/dev/null || printf '')"
        ;;
    esac
    risk="$(file_risk "$path" "$size" "spotlight")"
    append_event "$birth_epoch" "$birth" "$(user_from_artifact_path "$path")" "Spotlight/Archivos" "Creación indexada" "Spotlight" "$path" "Tamaño: $size bytes. Procedencia: $wherefrom" "$source_rel" "media" "$risk" ""
    if [ -n "$modified_epoch" ] && [ "$modified_epoch" != "$birth_epoch" ]; then
      append_event "$modified_epoch" "$modified" "$(user_from_artifact_path "$path")" "Spotlight/Archivos" "Modificación indexada" "Spotlight" "$path" "Tamaño: $size bytes. Procedencia: $wherefrom" "$source_rel" "media" "$risk" ""
    fi
    if [ -n "$last_used_epoch" ]; then
      append_event "$last_used_epoch" "$last_used_raw" "$(user_from_artifact_path "$path")" "Spotlight/Archivos" "Último uso indexado" "Spotlight" "$path" "Procedencia: $wherefrom" "$source_rel" "media" "$risk" ""
    fi
  done < "$combined"
}

parse_login_sessions() {
  src="$CASE_DIR/02_live/last.txt"
  [ -f "$src" ] || return 0
  source_rel="$(source_relative "$src")"
  source_hash="$(source_sha256 "$src")"
  current_year="$(date '+%Y')"
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    case "$line" in wtmp\ begins*|reboot*|shutdown*) continue ;; esac
    user_name="$(printf '%s' "$line" | awk '{print $1}')"
    [ -n "$user_name" ] || continue
    mdtime="$(printf '%s' "$line" | awk '{for(i=1;i<=NF;i++) if($i ~ /^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$/ && $(i+1) ~ /^[0-9]+$/ && $(i+2) ~ /^[0-9][0-9]:[0-9][0-9]$/){print $i" "$(i+1)" "$(i+2); exit}}')"
    epoch=""
    if [ -n "$mdtime" ]; then
      epoch="$(/bin/date -j -f '%Y %b %e %H:%M' "$current_year $mdtime" '+%s' 2>/dev/null || printf '')"
      if [ -n "$epoch" ] && [ "$epoch" -gt $((START_EPOCH + 86400)) ]; then
        prior_year=$((current_year - 1))
        epoch="$(/bin/date -j -f '%Y %b %e %H:%M' "$prior_year $mdtime" '+%s' 2>/dev/null || printf '')"
      fi
    fi
    host="$(printf '%s' "$line" | awk '{print $3}')"
    risk="info"
    case "$host" in console|ttys*|tty*|'') ;; *) risk="low" ;; esac
    append_event "$epoch" "$(iso_from_epoch "$epoch")" "$user_name" "Sesiones" "Inicio/sesión registrada" "last/wtmp" "$host" "$line" "$source_rel" "media" "$risk" "$source_hash"
  done < "$src"
}

parse_shell_histories() {
  analysis_log "Parsing shell histories"
  find "$FS_DIR" -type f \( -name '.zsh_history' -o -name '.bash_history' \) -print0 2>/dev/null | while IFS= read -r -d '' src; do
    user_name="$(user_from_artifact_path "$src")"
    source_rel="$(source_relative "$src")"
    source_hash="$(source_sha256 "$src")"
    shell_name="$(basename "$src")"
    while IFS= read -r line || [ -n "$line" ]; do
      [ -n "$line" ] || continue
      epoch=""; command_text="$line"
      case "$line" in
        ': '[0-9]*':'*';'*)
          epoch="$(printf '%s' "$line" | sed -E 's/^: ([0-9]+):[0-9]+;.*/\1/')"
          command_text="${line#*;}"
          ;;
      esac
      command_text="$(redact_sensitive "$command_text")"
      risk="$(command_risk "$command_text")"
      action="Comando ejecutado"
      case "$(printf '%s' "$command_text" | tr '[:upper:]' '[:lower:]')" in
        *"scp "*|*"sftp "*|*"rsync "*|*"rclone "*|*"curl "*"--upload-file"*) action="Posible transferencia por terminal" ;;
        *"zip "*|*"tar "*|*"7z "*) action="Posible preparación/compresión" ;;
        *"rm "*|*"srm "*|*"shred "*) action="Posible eliminación por terminal" ;;
      esac
      append_event "$epoch" "$(iso_from_epoch "$epoch")" "$user_name" "Terminal" "$action" "$shell_name" "$command_text" "Historial de shell" "$source_rel" "alta" "$risk" "$source_hash"
    done < "$src"
  done
}

parse_unified_compact() {
  src="$CASE_DIR/05_unified_logs/leak_relevant_${LOG_DAYS}d.compact.txt"
  [ -f "$src" ] || src="$CASE_DIR/05_unified_logs/leak_relevant_${LOG_DAYS}d.txt"
  [ -f "$src" ] || return 0
  analysis_log "Parsing Unified Logs"
  source_rel="$(source_relative "$src")"
  source_hash="$(source_sha256 "$src")"
  while IFS= read -r line; do
    printf '%s' "$line" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2} ' || continue
    raw_ts="$(printf '%s' "$line" | sed -E 's/^([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2})(\.[0-9]+)?([+-][0-9]{4}).*/\1\3/')"
    epoch="$(/bin/date -j -f '%Y-%m-%d %H:%M:%S%z' "$raw_ts" '+%s' 2>/dev/null || printf '')"
    [ -n "$epoch" ] || continue
    line_lc="$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')"
    category="Sistema"; action="Evento relevante"; risk="info"
    case "$line_lc" in
      *airdrop*|*sharingd*) category="AirDrop/Compartición"; action="Actividad de compartición"; risk="high" ;;
      *mounted*|*unmounted*|*diskarbitrationd*|*" usb "*) category="Dispositivos externos"; action="Montaje/actividad de volumen"; risk="medium" ;;
      *dropbox*|*onedrive*|*google\ drive*|*icloud*|*fileproviderd*) category="Nube"; action="Actividad de sincronización"; risk="medium" ;;
      *" scp"*|*" sftp"*|*" rsync"*|*sshd*) category="Transferencia remota"; action="Actividad SSH/transferencia"; risk="high" ;;
    esac
    case "$line_lc" in *upload*|*share*|*send*) [ "$category" = "Nube" ] && risk="high" ;; esac
    append_event "$epoch" "$(iso_from_epoch "$epoch")" "system" "$category" "$action" "Unified Logging" "" "$line" "$source_rel" "media" "$risk" "$source_hash"
  done < "$src"
}

parse_generic_transfer_logs() {
  analysis_log "Parsing cloud and transfer client logs"
  find "$FS_DIR" -type f \( -name '*.log' -o -name '*.trace' -o -name '*.txt' \) -print0 2>/dev/null | while IFS= read -r -d '' src; do
    path_lc="$(printf '%s' "$src" | tr '[:upper:]' '[:lower:]')"
    case "$path_lc" in
      *dropbox*|*drivefs*|*google\ drive*|*onedrive*|*nextcloud*|*megasync*|*cyberduck*|*filezilla*|*transmit*|*teamviewer*|*anydesk*) ;;
      *) continue ;;
    esac
    user_name="$(user_from_artifact_path "$src")"
    source_rel="$(source_relative "$src")"
    source_hash="$(source_sha256 "$src")"
    grep -a -i -E 'upload|uploaded|download|downloaded|sync|synced|share|shared|transfer|delete|deleted|remove|removed|move|moved|copy|copied|login|connect|session' "$src" 2>/dev/null | while IFS= read -r line; do
      line="$(redact_sensitive "$line")"
      raw_ts="$(printf '%s' "$line" | sed -nE 's/^.*([0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2})(\.[0-9]+)?(Z|[+-][0-9]{2}:?[0-9]{2})?.*$/\1\3/p' | head -n 1)"
      epoch=""
      if [ -n "$raw_ts" ]; then
        compact_ts="$(printf '%s' "$raw_ts" | sed -E 's/T/ /; s/Z$/+0000/; s/([+-][0-9]{2}):([0-9]{2})$/\1\2/')"
        case "$compact_ts" in
          *[+-][0-9][0-9][0-9][0-9]) epoch="$(/bin/date -j -f '%Y-%m-%d %H:%M:%S%z' "$compact_ts" '+%s' 2>/dev/null || printf '')" ;;
          *) epoch="$(/bin/date -j -f '%Y-%m-%d %H:%M:%S' "$compact_ts" '+%s' 2>/dev/null || printf '')" ;;
        esac
      fi
      line_lc="$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')"
      category="Nube"; action="Actividad de cliente"; risk="medium"
      case "$path_lc" in *cyberduck*|*filezilla*|*transmit*|*teamviewer*|*anydesk*) category="Transferencia/Acceso remoto" ;; esac
      case "$line_lc" in
        *upload*|*shared*|*" share "*|*sent*) action="Posible subida/compartición"; risk="high" ;;
        *download*) action="Descarga"; risk="info" ;;
        *delete*|*remove*) action="Eliminación registrada"; risk="medium" ;;
        *login*|*connect*|*session*) action="Sesión/conexión"; risk="medium" ;;
        *sync*) action="Sincronización"; risk="medium" ;;
      esac
      append_event "$epoch" "$raw_ts" "$user_name" "$category" "$action" "$(basename "$(dirname "$src")")" "" "$line" "$source_rel" "baja" "$risk" "$source_hash"
    done
  done
}

parse_persistence_plists() {
  analysis_log "Parsing persistence artifacts"
  find "$FS_DIR" -type f \( -path '*/Library/LaunchAgents/*.plist' -o -path '*/Library/LaunchDaemons/*.plist' \) -print0 2>/dev/null | while IFS= read -r src; do
    user_name="$(user_from_artifact_path "$src")"
    source_rel="$(source_relative "$src")"
    source_hash="$(source_sha256 "$src")"
    epoch="$(/usr/bin/stat -f '%m' "$src" 2>/dev/null || printf '')"
    ts="$(stat_time m "$src")"
    plist_text="$(/usr/bin/plutil -p "$src" 2>/dev/null | tr '\r\n\t' '   ')"
    label="$(printf '%s' "$plist_text" | sed -nE 's/.*"Label" => "([^"]+)".*/\1/p')"
    [ -n "$label" ] || label="$(basename "$src")"
    risk="low"
    case "$(printf '%s' "$plist_text" | tr '[:upper:]' '[:lower:]')" in
      *"/tmp/"*|*"/private/tmp/"*|*"/users/shared/"*|*"curl "*|*"osascript"*|*"python"*|*"nc "*) risk="high" ;;
    esac
    append_event "$epoch" "$ts" "$user_name" "Persistencia" "LaunchAgent/Daemon observado" "$label" "$source_rel" "$plist_text" "$source_rel" "media" "$risk" "$source_hash"
  done
}

parse_install_history() {
  src="$FS_DIR/Library/Receipts/InstallHistory.plist"
  [ -f "$src" ] || return 0
  command -v osascript >/dev/null 2>&1 || return 0
  source_rel="$(source_relative "$src")"
  source_hash="$(source_sha256 "$src")"
  json="$ANALYSIS_WORK/install_history.json"
  js="$ANALYSIS_WORK/install_history.js"
  /usr/bin/plutil -convert json -o "$json" "$src" 2>>"$ANALYSIS_ERROR_LOG" || return 0
  cat > "$js" <<'JXA'
ObjC.import('Foundation');
function run(argv) {
  var p = argv[0];
  var d = $.NSData.dataWithContentsOfFile(p);
  var s = $.NSString.alloc.initWithDataEncoding(d, $.NSUTF8StringEncoding).js;
  var a = JSON.parse(s);
  a.forEach(function(x) {
    var dt = x.date || '';
    var name = x.displayName || '';
    var ver = x.displayVersion || '';
    var proc = x.processName || '';
    var pkgs = (x.packageIdentifiers || []).join(', ');
    var line = [dt,name,ver,proc,pkgs].join('\u001f') + '\n';
    $.NSFileHandle.fileHandleWithStandardOutput.writeData($(line).dataUsingEncoding($.NSUTF8StringEncoding));
  });
}
JXA
  /usr/bin/osascript -l JavaScript "$js" "$json" 2>>"$ANALYSIS_ERROR_LOG" | while IFS=$'\037' read -r ts name version process_name packages; do
    [ -n "$ts" ] || continue
    compact="$(printf '%s' "$ts" | sed -E 's/\.[0-9]+Z$/Z/; s/T/ /; s/Z$/+0000/')"
    epoch="$(/bin/date -j -f '%Y-%m-%d %H:%M:%S%z' "$compact" '+%s' 2>/dev/null || printf '')"
    append_event "$epoch" "$ts" "system" "Software" "Instalación registrada" "$process_name" "$name $version" "Paquetes: $packages" "$source_rel" "alta" "low" "$source_hash"
  done
}

parse_praudit_report() {
  src="$CASE_DIR/08_reports/openbsm_praudit.txt"
  [ -f "$src" ] || return 0
  source_rel="$(source_relative "$src")"
  source_hash="$(source_sha256 "$src")"
  grep -a -i -E 'execve|open|rename|unlink|mount|login|logout|ssh|scp|sftp|rsync|curl|zip|tar|dropbox|onedrive|sharingd|connect' "$src" 2>/dev/null | while IFS= read -r line; do
    raw_date="$(printf '%s' "$line" | sed -nE 's/^.*((Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [ 0-9][0-9] [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4}).*$/\1/p' | head -n 1)"
    epoch=""
    [ -n "$raw_date" ] && epoch="$(/bin/date -j -f '%a %b %e %H:%M:%S %Y' "$raw_date" '+%s' 2>/dev/null || printf '')"
    line_lc="$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')"
    action="Evento OpenBSM"; risk="info"
    case "$line_lc" in
      *execve*) action="Ejecución auditada" ;;
      *rename*|*unlink*) action="Cambio o eliminación auditada"; risk="medium" ;;
      *mount*) action="Montaje auditado"; risk="medium" ;;
      *login*|*logout*) action="Sesión auditada" ;;
      *scp*|*sftp*|*rsync*|*rclone*|*"curl "*) action="Posible transferencia auditada"; risk="high" ;;
    esac
    append_event "$epoch" "$(iso_from_epoch "$epoch")" "system" "OpenBSM" "$action" "praudit" "" "$line" "$source_rel" "baja" "$risk" "$source_hash"
  done
}

parse_live_snapshots() {
  epoch="$(/bin/date -j -u -f '%Y-%m-%dT%H:%M:%SZ' "$START_UTC" '+%s' 2>/dev/null || date '+%s')"
  src="$CASE_DIR/03_network/lsof_network.txt"
  if [ -f "$src" ]; then
    source_rel="$(source_relative "$src")"; source_hash="$(source_sha256 "$src")"
    tail -n +2 "$src" 2>/dev/null | while IFS= read -r line; do
      [ -n "$line" ] || continue
      command_name="$(printf '%s' "$line" | awk '{print $1}')"
      user_name="$(printf '%s' "$line" | awk '{print $3}')"
      endpoint="$(printf '%s' "$line" | awk '{for(i=9;i<=NF;i++) printf "%s%s",$i,(i<NF?" ":"") }')"
      risk="info"
      case "$(printf '%s' "$command_name" | tr '[:upper:]' '[:lower:]')" in ssh|scp|sftp|rsync|rclone|nc|ncat|curl|python*|osascript) risk="medium" ;; esac
      case "$endpoint" in *ESTABLISHED*) [ "$risk" = "info" ] && risk="low" ;; esac
      append_event "$epoch" "$START_UTC" "$user_name" "Red" "Conexión/socket activo al adquirir" "$command_name" "$endpoint" "$line" "$source_rel" "alta" "$risk" "$source_hash"
    done
  fi

  src="$CASE_DIR/02_live/ps_process_tree.txt"
  if [ -f "$src" ]; then
    source_rel="$(source_relative "$src")"; source_hash="$(source_sha256 "$src")"
    tail -n +2 "$src" 2>/dev/null | while IFS= read -r line; do
      [ -n "$line" ] || continue
      user_name="$(printf '%s' "$line" | awk '{print $1}')"
      command_name="$(printf '%s' "$line" | awk '{print $NF}')"
      risk="info"
      case "$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')" in
        *rclone*|*" scp "*|*" sftp "*|*" rsync "*|*" nc "*|*" --upload-file"*) risk="high" ;;
        *teamviewer*|*anydesk*|*cyberduck*|*filezilla*|*dropbox*|*onedrive*|*drivefs*) risk="medium" ;;
      esac
      append_event "$epoch" "$START_UTC" "$user_name" "Procesos" "Proceso activo al adquirir" "$command_name" "" "$line" "$source_rel" "alta" "$risk" "$source_hash"
    done
  fi
}

parse_all_databases() {
  analysis_log "Discovering and parsing SQLite artifacts"
  find "$FS_DIR" -type f -print0 2>/dev/null | while IFS= read -r -d '' src; do
    case "$src" in
      */Library/Safari/History.db) parse_safari_history "$src" ;;
      */Google/Chrome/*/History|*/Microsoft\ Edge/*/History|*/BraveSoftware/Brave-Browser/*/History|*/Chromium/*/History|*/Arc/User\ Data/*/History)
        browser="Chromium"
        case "$src" in *Google/Chrome*) browser="Google Chrome" ;; *Microsoft\ Edge*) browser="Microsoft Edge" ;; *BraveSoftware*) browser="Brave" ;; *Arc/User\ Data*) browser="Arc" ;; esac
        parse_chromium_history "$src" "$browser"
        ;;
      */Firefox/Profiles/*/places.sqlite) parse_firefox_history "$src" ;;
      */com.apple.LaunchServices.QuarantineEventsV2) parse_quarantine_db "$src" ;;
      */com.apple.TCC/TCC.db) parse_tcc_db "$src" ;;
      */Knowledge/knowledgeC.db) parse_knowledgec_db "$src" ;;
      */Library/Messages/chat.db) parse_messages_db "$src" ;;
      */Mail/*/MailData/Envelope\ Index|*/Mail/*/*/Envelope\ Index|*/Mail/*/Envelope\ Index) parse_mail_envelope "$src" ;;
    esac
  done
}

generate_coverage() {
  COVERAGE_TSV="$REPORT_DIR/artifact_coverage.tsv"
  printf 'artifact_group\tstatus\titems\tnotes\n' > "$COVERAGE_TSV"
  count_pattern() { find "$FS_DIR" -type f -path "$1" 2>/dev/null | wc -l | tr -d ' '; }
  browser_count="$(find "$FS_DIR" -type f \( -name History -o -name History.db -o -name places.sqlite \) 2>/dev/null | wc -l | tr -d ' ')"
  quarantine_count="$(find "$FS_DIR" -type f -name 'com.apple.LaunchServices.QuarantineEventsV2' 2>/dev/null | wc -l | tr -d ' ')"
  knowledge_count="$(find "$FS_DIR" -type f -name 'knowledgeC.db' 2>/dev/null | wc -l | tr -d ' ')"
  tcc_count="$(find "$FS_DIR" -type f -name 'TCC.db' 2>/dev/null | wc -l | tr -d ' ')"
  mail_count="$(find "$FS_DIR" -type f -name 'Envelope Index' 2>/dev/null | wc -l | tr -d ' ')"
  message_count="$(find "$FS_DIR" -type f -name 'chat.db' 2>/dev/null | wc -l | tr -d ' ')"
  shell_count="$(find "$FS_DIR" -type f \( -name '.zsh_history' -o -name '.bash_history' \) 2>/dev/null | wc -l | tr -d ' ')"
  persistence_count="$(find "$FS_DIR" -type f \( -path '*/Library/LaunchAgents/*.plist' -o -path '*/Library/LaunchDaemons/*.plist' \) 2>/dev/null | wc -l | tr -d ' ')"
  cloud_log_count="$(find "$FS_DIR" -type f \( -name '*.log' -o -name '*.trace' -o -name '*.txt' \) 2>/dev/null | grep -Ei 'Dropbox|DriveFS|Google Drive|OneDrive|Nextcloud|MEGAsync|Cyberduck|FileZilla|Transmit|TeamViewer|AnyDesk' | wc -l | tr -d ' ')"
  fsevents_count="$(find "$FS_DIR" -type f -path '*/.fseventsd/*' 2>/dev/null | wc -l | tr -d ' ')"
  spotlight_count="$(find "$FS_DIR" -type f -path '*/.Spotlight-V100/*' 2>/dev/null | wc -l | tr -d ' ')"
  audit_count="$(find "$FS_DIR" -type f -path '*/private/var/audit/*' 2>/dev/null | wc -l | tr -d ' ')"
  recent_count="$(awk 'END{print (NR>0?NR-1:0)}' "$RECENT_TSV" 2>/dev/null || printf '0')"

  printf 'Navegadores\tAnalizado\t%s\tVisitas y descargas de Safari, Chromium y Firefox mediante SQLite.\n' "$browser_count" >> "$COVERAGE_TSV"
  printf 'Quarantine Events\tAnalizado\t%s\tAgente, URL de origen, URL de datos y fecha.\n' "$quarantine_count" >> "$COVERAGE_TSV"
  printf 'KnowledgeC\tAnalizado\t%s\tEventos temporales normalizados; interpretación dependiente de la versión de macOS.\n' "$knowledge_count" >> "$COVERAGE_TSV"
  printf 'TCC\tAnalizado\t%s\tPermisos y fecha de última modificación.\n' "$tcc_count" >> "$COVERAGE_TSV"
  printf 'Apple Mail Envelope Index\tAnalizado parcial\t%s\tMetadatos de mensajes según el esquema disponible; la dirección del correo puede depender del buzón.\n' "$mail_count" >> "$COVERAGE_TSV"
  printf 'Messages\tAnalizado si fue adquirido\t%s\tMetadatos y adjuntos; no se incorpora el cuerpo de los mensajes.\n' "$message_count" >> "$COVERAGE_TSV"
  printf 'Historiales de terminal\tAnalizado\t%s\tLos comandos sin timestamp se separan como evidencias sin fecha.\n' "$shell_count" >> "$COVERAGE_TSV"
  printf 'Logs de nube y transferencia\tAnalizado heurístico\t%s\tSe filtran líneas asociadas a subida, descarga, sincronización, sesiones y borrado.\n' "$cloud_log_count" >> "$COVERAGE_TSV"
  printf 'Persistencias\tAnalizado\t%s\tLaunchAgents y LaunchDaemons con fecha, configuración y reglas de riesgo.\n' "$persistence_count" >> "$COVERAGE_TSV"
  printf 'Inventario de archivos recientes\tAnalizado\t%s\tCreación, modificación, cambio de metadatos y último acceso.\n' "$recent_count" >> "$COVERAGE_TSV"
  printf 'Unified Logs\tAnalizado filtrado\t%s\tAirDrop, soportes externos, nube y transferencias remotas durante la ventana seleccionada.\n' "$( [ -f "$CASE_DIR/05_unified_logs/leak_relevant_${LOG_DAYS}d.compact.txt" ] && echo 1 || echo 0 )" >> "$COVERAGE_TSV"
  printf 'FSEvents\tPreservado, no decodificado\t%s\tEl formato no conserva una marca temporal exacta por registro y requiere un parser forense especializado.\n' "$fsevents_count" >> "$COVERAGE_TSV"
  printf 'Spotlight bruto\tPreservado / metadatos parciales\t%s\tSe analizan resultados mdfind; el store bruto requiere un parser especializado.\n' "$spotlight_count" >> "$COVERAGE_TSV"
  printf 'OpenBSM audit\tDecodificado parcial / preservado\t%s\tSe filtran eventos relevantes mediante praudit cuando está disponible; el conjunto binario original permanece preservado.\n' "$audit_count" >> "$COVERAGE_TSV"
}

generate_findings() {
  printf 'risk\tfirst_timestamp\tlast_timestamp\tcategory\taction\tcount\tassessment\n' > "$FINDINGS_TSV"
  awk -F'\t' 'NR>1 && ($10=="high" || $10=="critical") {
      k=$3 FS $4 FS $10;
      if (!(k in first)) first[k]=$1;
      last[k]=$1; count[k]++; cat[k]=$3; act[k]=$4; risk[k]=$10
    }
    END {
      for (k in count) {
        assessment="Indicadores automáticos que requieren correlación y validación pericial; no constituyen por sí solos prueba de exfiltración.";
        printf "%s\t%s\t%s\t%s\t%s\t%d\t%s\n", risk[k],first[k],last[k],cat[k],act[k],count[k],assessment
      }
    }' "$TIMELINE_TSV" | sort -t $'\t' -k1,1 -k2,2 >> "$FINDINGS_TSV"

  archives="$(awk -F'\t' 'NR>1 && $3=="Archivos" && tolower($6) ~ /\.(zip|7z|rar|tar|tgz|dmg|iso)$/ {c++} END{print c+0}' "$TIMELINE_TSV")"
  transfers="$(awk -F'\t' 'NR>1 && ($3 ~ /Nube|AirDrop|Transferencia/ || $4 ~ /subida|transferencia|compartición/) {c++} END{print c+0}' "$TIMELINE_TSV")"
  if [ "$archives" -gt 0 ] && [ "$transfers" -gt 0 ]; then
    printf 'medium\t\t\tCorrelación\tPreparación y transferencia coexistentes\t%s\tSe han observado %s eventos asociados a archivos contenedores y %s eventos de transferencia/compartición. Deben correlacionarse por usuario, ruta y proximidad temporal.\n' "$((archives + transfers))" "$archives" "$transfers" >> "$FINDINGS_TSV"
  fi

  if [ -s "$TIMELINE_RAW" ]; then
    LC_ALL=C sort -t $'\t' -k1,1n "$TIMELINE_RAW" | awk -F'\t' '
      function isarchive(p){p=tolower(p); return p ~ /\.(zip|7z|rar|tar|tgz|tar.gz|dmg|iso)$/}
      function istransfer(c,a){return c ~ /Nube|AirDrop|Transferencia/ || tolower(a) ~ /subida|transferencia|compartición|sincronización/}
      {
        epoch=$1; ts=$2; user=$3; cat=$4; action=$5; object=$7;
        if (cat=="Archivos" && isarchive(object)) {last_epoch[user]=epoch; last_ts[user]=ts; last_obj[user]=object}
        if (istransfer(cat,action) && user in last_epoch && epoch-last_epoch[user]>=0 && epoch-last_epoch[user]<=1800) {
          key=user SUBSEP last_epoch[user] SUBSEP epoch SUBSEP action;
          if (!seen[key]++) printf "high\t%s\t%s\tCorrelación temporal\tArchivo contenedor seguido de transferencia\t2\tUsuario %s: %s precede en %d segundos a %s. Validar destino, contenido y correspondencia entre ambos eventos.\n",last_ts[user],ts,user,last_obj[user],epoch-last_epoch[user],action;
        }
      }' >> "$FINDINGS_TSV"
  fi
}

html_escape_shell() {
  printf '%s' "$1" | sed -e 's/\&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g' -e "s/'/\&#39;/g"
}

html_escape_awk='function h(s){gsub(/\&/,"\\&amp;",s);gsub(/</,"\\&lt;",s);gsub(/>/,"\\&gt;",s);gsub(/\"/,"\\&quot;",s);gsub(/\047/,"\\&#39;",s);return s}'

generate_html_report() {
  total_events="$(awk 'END{print (NR>0?NR-1:0)}' "$TIMELINE_TSV")"
  undated_events="$(awk 'END{print (NR>0?NR-1:0)}' "$UNDATED_TSV")"
  high_events="$(awk -F'\t' 'NR>1 && ($10=="high" || $10=="critical") {c++} END{print c+0}' "$TIMELINE_TSV")"
  medium_events="$(awk -F'\t' 'NR>1 && $10=="medium" {c++} END{print c+0}' "$TIMELINE_TSV")"
  users_count="$(awk -F'\t' 'NR>1 && $2!="" {u[$2]=1} END{for(k in u)c++;print c+0}' "$TIMELINE_TSV")"
  categories_count="$(awk -F'\t' 'NR>1 && $3!="" {u[$3]=1} END{for(k in u)c++;print c+0}' "$TIMELINE_TSV")"
  first_event="$(awk -F'\t' 'NR==2{print $1; exit}' "$TIMELINE_TSV")"
  last_event="$(awk -F'\t' 'END{if(NR>1)print $1}' "$TIMELINE_TSV")"

  cat > "$HTML_REPORT" <<HTML
<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>QK14 MacLeak — Timeline $SAFE_CASE_ID</title>
<style>
:root{--bg:#0b1220;--panel:#111b2e;--panel2:#17233a;--text:#e8eef8;--muted:#9fb0c8;--line:#2b3a55;--accent:#51b7ff;--critical:#ff405c;--high:#ff7a45;--medium:#f5c451;--low:#6fca8c;--info:#7da8d9}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}header{padding:28px 32px;background:linear-gradient(135deg,#111b2e,#172a47);border-bottom:1px solid var(--line)}h1{margin:0 0 6px;font-size:26px}.subtitle{color:var(--muted)}main{padding:24px 28px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:20px}.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px}.card b{display:block;font-size:25px;margin-top:4px}.controls{position:sticky;top:0;z-index:5;display:grid;grid-template-columns:minmax(240px,2fr) repeat(3,minmax(130px,1fr)) auto;gap:10px;padding:12px;background:rgba(11,18,32,.96);border:1px solid var(--line);border-radius:12px;margin-bottom:12px;backdrop-filter:blur(8px)}input,select,button{border:1px solid var(--line);border-radius:8px;background:var(--panel2);color:var(--text);padding:9px 10px}button{cursor:pointer}button:hover{border-color:var(--accent)}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:12px;background:var(--panel)}table{border-collapse:collapse;width:100%;min-width:1500px}th,td{padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top;text-align:left}th{position:sticky;top:0;background:#16243b;z-index:2;font-size:12px;text-transform:uppercase;letter-spacing:.04em}tr:hover td{background:#142039}.risk{display:inline-block;padding:2px 8px;border-radius:999px;font-weight:700;font-size:11px;text-transform:uppercase}.risk-critical{background:var(--critical);color:white}.risk-high{background:var(--high);color:#1b0d04}.risk-medium{background:var(--medium);color:#2b2100}.risk-low{background:var(--low);color:#06180b}.risk-info{background:var(--info);color:#06111e}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}.details{max-width:520px;white-space:pre-wrap;overflow-wrap:anywhere}.path{max-width:420px;overflow-wrap:anywhere}.section{margin:28px 0 12px}.note{background:#152238;border-left:4px solid var(--accent);padding:12px 14px;border-radius:6px;color:var(--muted)}.hidden{display:none!important}.counter{color:var(--muted);margin:8px 2px}.findings{min-width:1000px}.footer{color:var(--muted);font-size:12px;margin-top:22px}@media(max-width:900px){main{padding:16px}.controls{grid-template-columns:1fr 1fr}.controls input:first-child{grid-column:1/-1}}
</style>
</head>
<body>
<header><h1>QK14 MacLeak — Timeline de actividad</h1><div class="subtitle">Procedimiento: $(html_escape_shell "$CASE_ID") · Equipo: $(html_escape_shell "$(hostname 2>/dev/null)") · Informe generado: $(now_utc)</div></header>
<main>
<div class="cards">
<div class="card">Eventos con fecha<b>$total_events</b></div>
<div class="card">Riesgo alto/crítico<b>$high_events</b></div>
<div class="card">Riesgo medio<b>$medium_events</b></div>
<div class="card">Usuarios observados<b>$users_count</b></div>
<div class="card">Categorías<b>$categories_count</b></div>
<div class="card">Eventos sin fecha<b>$undated_events</b></div>
</div>
<div class="note"><b>Alcance automático.</b> El informe correlaciona artefactos adquiridos, pero sus clasificaciones son indicadores orientativos. Las fechas de acceso, KnowledgeC, logs de terceros y eventos derivados de metadatos requieren validación frente al contexto, zona horaria y posibles efectos de la adquisición en vivo. FSEvents y Spotlight sin parser especializado permanecen preservados como evidencia bruta.</div>
<h2 class="section">Hallazgos automáticos</h2>
<div class="table-wrap"><table class="findings"><thead><tr><th>Riesgo</th><th>Primero</th><th>Último</th><th>Categoría</th><th>Indicador</th><th>N.º</th><th>Valoración</th></tr></thead><tbody>
HTML

  awk -F'\t' "$html_escape_awk NR>1 {r=tolower(\$1); printf \"<tr><td><span class='risk risk-%s'>%s</span></td><td class='mono'>%s</td><td class='mono'>%s</td><td>%s</td><td>%s</td><td>%s</td><td class='details'>%s</td></tr>\\n\",h(r),h(\$1),h(\$2),h(\$3),h(\$4),h(\$5),h(\$6),h(\$7)}" "$FINDINGS_TSV" >> "$HTML_REPORT"

  cat >> "$HTML_REPORT" <<'HTML'
</tbody></table></div>
<h2 class="section">Cobertura de artefactos</h2>
<div class="table-wrap"><table class="findings"><thead><tr><th>Grupo</th><th>Estado</th><th>Elementos</th><th>Notas</th></tr></thead><tbody>
HTML

  awk -F'\t' "$html_escape_awk NR>1 {printf \"<tr><td>%s</td><td>%s</td><td>%s</td><td class='details'>%s</td></tr>\\n\",h(\$1),h(\$2),h(\$3),h(\$4)}" "$COVERAGE_TSV" >> "$HTML_REPORT"

  cat >> "$HTML_REPORT" <<'HTML'
</tbody></table></div>
<h2 class="section">Cronología unificada</h2>
<div class="controls">
<input id="q" type="search" placeholder="Buscar usuario, archivo, URL, proceso, detalle…">
<select id="category"><option value="">Todas las categorías</option></select>
<select id="risk"><option value="">Todos los riesgos</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>info</option></select>
<select id="user"><option value="">Todos los usuarios</option></select>
<input id="fromDate" type="datetime-local" title="Desde">
<input id="toDate" type="datetime-local" title="Hasta">
<button id="export">Exportar visibles CSV</button>
</div>
<div class="counter" id="counter"></div>
<div class="table-wrap"><table id="timeline"><thead><tr><th>Fecha/hora</th><th>Usuario</th><th>Categoría</th><th>Acción</th><th>Aplicación/proceso</th><th>Objeto</th><th>Detalles</th><th>Fuente</th><th>Confianza</th><th>Riesgo</th><th>SHA-256 fuente</th></tr></thead><tbody>
HTML

  awk -F'\t' "$html_escape_awk NR>1 {r=tolower(\$10); printf \"<tr data-category='\" h(\$3) \"' data-risk='\" h(r) \"' data-user='\" h(\$2) \"'><td class='mono'>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class='path'>%s</td><td class='details'>%s</td><td class='path mono'>%s</td><td>%s</td><td><span class='risk risk-%s'>%s</span></td><td class='mono'>%s</td></tr>\\n\",h(\$1),h(\$2),h(\$3),h(\$4),h(\$5),h(\$6),h(\$7),h(\$8),h(\$9),h(r),h(\$10),h(\$11)}" "$TIMELINE_TSV" >> "$HTML_REPORT"

  cat >> "$HTML_REPORT" <<HTML
</tbody></table></div>
<h2 class="section">Evidencias sin fecha normalizable</h2>
<div class="note">Incluye principalmente comandos de historiales sin timestamp y líneas de aplicaciones sin una fecha verificable. No deben situarse artificialmente en la cronología.</div>
<div class="table-wrap"><table><thead><tr><th>Fecha original</th><th>Usuario</th><th>Categoría</th><th>Acción</th><th>Aplicación</th><th>Objeto</th><th>Detalles</th><th>Fuente</th><th>Confianza</th><th>Riesgo</th><th>SHA-256 fuente</th></tr></thead><tbody>
HTML

  awk -F'\t' "$html_escape_awk NR>1 {r=tolower(\$10); printf \"<tr><td class='mono'>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class='path'>%s</td><td class='details'>%s</td><td class='path mono'>%s</td><td>%s</td><td><span class='risk risk-%s'>%s</span></td><td class='mono'>%s</td></tr>\\n\",h(\$1),h(\$2),h(\$3),h(\$4),h(\$5),h(\$6),h(\$7),h(\$8),h(\$9),h(r),h(\$10),h(\$11)}" "$UNDATED_TSV" >> "$HTML_REPORT"

  cat >> "$HTML_REPORT" <<HTML
</tbody></table></div>
<div class="footer">Intervalo observado: ${first_event:-sin eventos} — ${last_event:-sin eventos}. Los ficheros TSV conservan la totalidad de los eventos normalizados y permiten análisis adicional.</div>
</main>
<script>
const rows=[...document.querySelectorAll('#timeline tbody tr')];
const q=document.getElementById('q'),category=document.getElementById('category'),risk=document.getElementById('risk'),user=document.getElementById('user'),fromDate=document.getElementById('fromDate'),toDate=document.getElementById('toDate'),counter=document.getElementById('counter');
function fill(select,key){[...new Set(rows.map(r=>r.dataset[key]).filter(Boolean))].sort((a,b)=>a.localeCompare(b,'es')).forEach(v=>{const o=document.createElement('option');o.value=v;o.textContent=v;select.appendChild(o)})}
fill(category,'category');fill(user,'user');
function eventTime(r){const t=r.cells[0].textContent.trim().replace(/([+-]\d{2})(\d{2})$/,function(_,a,b){return a+':'+b});const v=Date.parse(t);return Number.isNaN(v)?null:v}
function filter(){const needle=q.value.toLowerCase();const f=fromDate.value?Date.parse(fromDate.value):null;const t=toDate.value?Date.parse(toDate.value):null;let n=0;rows.forEach(r=>{const rt=eventTime(r);const dateOk=(f===null||rt===null||rt>=f)&&(t===null||rt===null||rt<=t);const ok=dateOk&&(!needle||r.textContent.toLowerCase().includes(needle))&&(!category.value||r.dataset.category===category.value)&&(!risk.value||r.dataset.risk===risk.value)&&(!user.value||r.dataset.user===user.value);r.classList.toggle('hidden',!ok);if(ok)n++});counter.textContent='Mostrando '+n.toLocaleString('es-ES')+' de '+rows.length.toLocaleString('es-ES')+' eventos';}
[q,category,risk,user,fromDate,toDate].forEach(x=>x.addEventListener('input',filter));filter();
function csv(v){return '"'+String(v).replace(/"/g,'""')+'"'}
document.getElementById('export').addEventListener('click',()=>{const visible=rows.filter(r=>!r.classList.contains('hidden'));const head=[...document.querySelectorAll('#timeline thead th')].map(x=>csv(x.textContent)).join(',');const body=visible.map(r=>[...r.cells].map(c=>csv(c.textContent.trim())).join(',')).join('\n');const blob=new Blob([head+'\n'+body],{type:'text/csv;charset=utf-8'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='QK14_timeline_filtrado.csv';a.click();URL.revokeObjectURL(a.href)});
</script>
</body></html>
HTML
}

generate_analysis() {
  REPORT_DIR="$CASE_DIR/08_reports"
  ANALYSIS_WORK="$REPORT_DIR/.analysis_work"
  ANALYSIS_LOG="$REPORT_DIR/analysis.log"
  ANALYSIS_ERROR_LOG="$REPORT_DIR/analysis_errors.log"
  TIMELINE_RAW="$ANALYSIS_WORK/timeline_raw.tsv"
  UNDATED_RAW="$ANALYSIS_WORK/undated_raw.tsv"
  TIMELINE_TSV="$REPORT_DIR/timeline_activity.tsv"
  UNDATED_TSV="$REPORT_DIR/undated_evidence.tsv"
  FINDINGS_TSV="$REPORT_DIR/automatic_findings.tsv"
  HTML_REPORT="$REPORT_DIR/QK14_MacLeak_Timeline.html"

  rm -rf "$ANALYSIS_WORK" 2>/dev/null || true
  mkdir -p "$ANALYSIS_WORK"
  : > "$ANALYSIS_LOG"
  : > "$ANALYSIS_ERROR_LOG"
  : > "$TIMELINE_RAW"
  : > "$UNDATED_RAW"
  analysis_log "ANALYSIS_START collector=$VERSION case=$CASE_ID"

  if ! command -v sqlite3 >/dev/null 2>&1; then
    analysis_error "sqlite3 not found; database artifacts cannot be parsed"
  else
    parse_all_databases
  fi
  parse_recent_inventory
  parse_shell_histories
  parse_unified_compact
  parse_generic_transfer_logs
  parse_persistence_plists
  parse_install_history
  parse_spotlight_reports
  parse_login_sessions
  parse_praudit_report
  parse_live_snapshots

  printf 'timestamp\tuser\tcategory\taction\tapplication_process\tobject\tdetails\tsource_artifact\tconfidence\trisk\tevidence_sha256\n' > "$TIMELINE_TSV"
  if [ -s "$TIMELINE_RAW" ]; then
    LC_ALL=C sort -t $'\t' -k1,1n -k2,2 "$TIMELINE_RAW" | awk -F'\t' 'BEGIN{OFS="\t"} !seen[$0]++ {$1=""; sub(/^\t/,""); print}' >> "$TIMELINE_TSV"
  fi

  printf 'timestamp_original\tuser\tcategory\taction\tapplication_process\tobject\tdetails\tsource_artifact\tconfidence\trisk\tevidence_sha256\n' > "$UNDATED_TSV"
  if [ -s "$UNDATED_RAW" ]; then
    LC_ALL=C sort -u "$UNDATED_RAW" >> "$UNDATED_TSV"
  fi

  generate_coverage
  generate_findings
  generate_html_report
  analysis_log "ANALYSIS_COMPLETE events=$(awk 'END{print NR-1}' "$TIMELINE_TSV") html=$(source_relative "$HTML_REPORT")"

  rm -rf "$ANALYSIS_WORK" 2>>"$ANALYSIS_ERROR_LOG" || true
}


# Warn if the destination appears to be on the same filesystem as the startup volume.
ROOT_DEVICE="$(df / 2>/dev/null | awk 'NR==2 {print $1}')"
DEST_DEVICE="$(df "$DEST_PARENT" 2>/dev/null | awk 'NR==2 {print $1}')"
if [ -n "$ROOT_DEVICE" ] && [ "$ROOT_DEVICE" = "$DEST_DEVICE" ]; then
  echo "ADVERTENCIA: el destino parece estar en el mismo sistema de archivos que macOS." >&2
  echo "Para una intervención forense es preferible un soporte externo." >&2
fi

COLLECTOR_PATH="$(cd "$(dirname "$0")" 2>/dev/null && pwd -P)/$(basename "$0")"
COLLECTOR_HASH="$(/usr/bin/shasum -a 256 "$COLLECTOR_PATH" 2>/dev/null | awk '{print $1}')"

cat > "$CASE_META" <<META
collector_name=QK14 MacLeak Collector
collector_version=$VERSION
collector_sha256=$COLLECTOR_HASH
case_id=$CASE_ID
safe_case_id=$SAFE_CASE_ID
start_utc=$START_UTC
host=$(hostname 2>/dev/null)
operator=${SUDO_USER:-root}
log_days=$LOG_DAYS
recent_days=$RECENT_DAYS
include_communications=$INCLUDE_COMMUNICATIONS
hash_recent_files=$HASH_RECENT_FILES
deep_collection=$DEEP_COLLECTION
auto_analysis=$AUTO_ANALYZE
destination=$CASE_DIR
root_device=$ROOT_DEVICE
destination_device=$DEST_DEVICE
META

copy_path "$COLLECTOR_PATH" "collector-original"
# Keep a second convenient copy outside the replicated filesystem tree.
cp -p "$COLLECTOR_PATH" "$CASE_DIR/10_collector/$(basename "$COLLECTOR_PATH")" 2>>"$ERROR_LOG" || true

printf 'sha256\tsize_bytes\tbirth_time\tmodified_time\tchanged_time\taccessed_time\tuser\tsource_path\tbirth_epoch\tmodified_epoch\tchanged_epoch\taccessed_epoch\n' > "$RECENT_TSV"

log_event "ACQUISITION_START version=$VERSION case=$CASE_ID destination=$CASE_DIR"
log_event "NOTICE Full Disk Access must be granted to the terminal application; sudo alone may not bypass macOS privacy controls"

# 1. System identification and storage.
run_cmd "local-time" "$CASE_DIR/01_system/date_local.txt" date
run_cmd "utc-time" "$CASE_DIR/01_system/date_utc.txt" date -u
run_cmd "sw-vers" "$CASE_DIR/01_system/sw_vers.txt" /usr/bin/sw_vers
run_cmd "uname" "$CASE_DIR/01_system/uname.txt" uname -a
run_cmd "uptime" "$CASE_DIR/01_system/uptime.txt" uptime
run_cmd "hostname" "$CASE_DIR/01_system/hostname.txt" hostname
run_cmd "system-profiler-core" "$CASE_DIR/01_system/system_profiler_core.txt" \
  /usr/sbin/system_profiler SPHardwareDataType SPSoftwareDataType SPStorageDataType SPNetworkDataType SPUSBDataType SPThunderboltDataType SPBluetoothDataType
run_cmd "system-profiler-apps" "$CASE_DIR/01_system/system_profiler_applications.txt" \
  /usr/sbin/system_profiler SPApplicationsDataType
run_cmd "ioreg-platform" "$CASE_DIR/01_system/ioreg_platform.txt" \
  /usr/sbin/ioreg -rd1 -c IOPlatformExpertDevice
run_cmd "ioreg-usb" "$CASE_DIR/01_system/ioreg_usb.txt" /usr/sbin/ioreg -p IOUSB -l -w 0
run_cmd "diskutil-list" "$CASE_DIR/01_system/diskutil_list.txt" /usr/sbin/diskutil list
run_cmd "diskutil-apfs" "$CASE_DIR/01_system/diskutil_apfs_list.txt" /usr/sbin/diskutil apfs list
run_cmd "diskutil-snapshots" "$CASE_DIR/01_system/diskutil_apfs_snapshots.txt" /usr/sbin/diskutil apfs listSnapshots /
run_cmd "mount" "$CASE_DIR/01_system/mount.txt" mount
run_cmd "df" "$CASE_DIR/01_system/df_h.txt" df -h
run_cmd "filevault" "$CASE_DIR/01_system/filevault_status.txt" /usr/bin/fdesetup status
run_cmd "time-machine-snapshots" "$CASE_DIR/01_system/time_machine_snapshots.txt" /usr/bin/tmutil listlocalsnapshots /
run_cmd "nvram" "$CASE_DIR/01_system/nvram.txt" /usr/sbin/nvram -xp
run_cmd "profiles" "$CASE_DIR/01_system/configuration_profiles.txt" /usr/bin/profiles show -type configuration
run_cmd "mdm-status" "$CASE_DIR/01_system/mdm_status.txt" /usr/bin/profiles status -type enrollment
run_cmd "software-update-history" "$CASE_DIR/01_system/software_update_history.txt" /usr/sbin/system_profiler SPInstallHistoryDataType

# 2. Live response.
run_cmd "processes" "$CASE_DIR/02_live/ps_auxww.txt" ps auxww
run_cmd "process-tree" "$CASE_DIR/02_live/ps_process_tree.txt" ps -axo user,pid,ppid,start,time,state,command
run_cmd "open-files" "$CASE_DIR/02_live/lsof_all.txt" /usr/sbin/lsof -nP
run_cmd "open-network-files" "$CASE_DIR/02_live/lsof_network.txt" /usr/sbin/lsof -nP -i
run_cmd "who" "$CASE_DIR/02_live/who.txt" who
run_cmd "w" "$CASE_DIR/02_live/w.txt" w
run_cmd "last" "$CASE_DIR/02_live/last.txt" last
run_cmd "users-dscl" "$CASE_DIR/02_live/users_uid.txt" /usr/bin/dscl . -list /Users UniqueID
run_cmd "groups-dscl" "$CASE_DIR/02_live/groups_gid.txt" /usr/bin/dscl . -list /Groups PrimaryGroupID
run_cmd "loginwindow" "$CASE_DIR/02_live/loginwindow_preferences.txt" /usr/bin/defaults read /Library/Preferences/com.apple.loginwindow
run_cmd "open-files-deleted" "$CASE_DIR/02_live/lsof_deleted.txt" /usr/sbin/lsof +L1

# 3. Network state.
run_cmd "ifconfig" "$CASE_DIR/03_network/ifconfig.txt" /sbin/ifconfig -a
run_cmd "netstat" "$CASE_DIR/03_network/netstat_anv.txt" /usr/sbin/netstat -anv
run_cmd "arp" "$CASE_DIR/03_network/arp.txt" /usr/sbin/arp -an
run_cmd "route-default" "$CASE_DIR/03_network/default_route.txt" /sbin/route -n get default
run_cmd "dns" "$CASE_DIR/03_network/scutil_dns.txt" /usr/sbin/scutil --dns
run_cmd "proxy" "$CASE_DIR/03_network/scutil_proxy.txt" /usr/sbin/scutil --proxy
run_cmd "network-services" "$CASE_DIR/03_network/network_services.txt" /usr/sbin/networksetup -listallnetworkservices
run_cmd "wifi" "$CASE_DIR/03_network/wifi_info.txt" /usr/sbin/system_profiler SPAirPortDataType

# 4. Persistence and security configuration.
run_cmd "launchctl-system" "$CASE_DIR/04_persistence/launchctl_system.txt" /bin/launchctl print system
CURRENT_UID="$(id -u "${SUDO_USER:-root}" 2>/dev/null || printf '0')"
run_cmd "launchctl-user" "$CASE_DIR/04_persistence/launchctl_gui_user.txt" /bin/launchctl print "gui/$CURRENT_UID"
run_cmd "background-tasks" "$CASE_DIR/04_persistence/sfltool_dumpbtm.txt" /usr/bin/sfltool dumpbtm
run_cmd "system-extensions" "$CASE_DIR/04_persistence/systemextensionsctl.txt" /usr/bin/systemextensionsctl list
run_cmd "loaded-kexts" "$CASE_DIR/04_persistence/kmutil_loaded.txt" /usr/bin/kmutil showloaded
run_cmd "crontab-root" "$CASE_DIR/04_persistence/crontab_root.txt" /usr/bin/crontab -l

copy_path "/Library/LaunchAgents" "persistence-system"
copy_path "/Library/LaunchDaemons" "persistence-system"
copy_path "/Library/PrivilegedHelperTools" "persistence-system"
copy_path "/Library/StartupItems" "persistence-system"
copy_path "/Library/ScriptingAdditions" "persistence-system"
copy_path "/Library/Internet Plug-Ins" "persistence-system"
copy_path "/etc/periodic" "persistence-system"
copy_path "/private/var/at" "persistence-system"
copy_path "/etc/ssh" "ssh-system"
copy_path "/Library/Preferences/SystemConfiguration" "network-configuration"
copy_sqlite_bundle "/Library/Application Support/com.apple.TCC/TCC.db" "tcc-system"
copy_path "/Library/Receipts/InstallHistory.plist" "installation-history"
copy_path "/private/var/db/receipts" "installation-receipts"
copy_path "/private/var/db/dslocal/nodes/Default/users" "local-users"
copy_path "/private/var/audit" "audit-logs"
if [ -x /usr/sbin/praudit ] && [ -d /private/var/audit ]; then
  run_shell "openbsm-praudit" "$CASE_DIR/08_reports/openbsm_praudit.txt" 'for f in /private/var/audit/*; do [ -f "$f" ] || continue; echo "### $f"; /usr/sbin/praudit -l "$f"; done'
fi
copy_path "/var/log" "system-logs"
copy_path "/Library/Logs" "system-logs"

# 5. Unified Logging. log collect produces a directory bundle.
if command -v log >/dev/null 2>&1; then
  log_event "CMD_START [unified-log-collect] last=${LOG_DAYS}d"
  /usr/bin/log collect --last "${LOG_DAYS}d" --output "$CASE_DIR/05_unified_logs/system_${LOG_DAYS}d.logarchive" \
    > "$CASE_DIR/05_unified_logs/log_collect_stdout.txt" 2>&1
  rc=$?
  if [ "$rc" -eq 0 ]; then
    log_event "CMD_OK [unified-log-collect]"
  else
    record_error "CMD_FAIL rc=$rc [unified-log-collect]"
  fi

  LEAK_PREDICATE='process == "sharingd" OR process == "diskarbitrationd" OR process == "sshd" OR process == "fileproviderd" OR eventMessage CONTAINS[c] "AirDrop" OR eventMessage CONTAINS[c] "USB" OR eventMessage CONTAINS[c] "mounted" OR eventMessage CONTAINS[c] "unmounted" OR eventMessage CONTAINS[c] "Dropbox" OR eventMessage CONTAINS[c] "OneDrive" OR eventMessage CONTAINS[c] "Google Drive" OR eventMessage CONTAINS[c] "iCloud" OR eventMessage CONTAINS[c] "scp" OR eventMessage CONTAINS[c] "sftp" OR eventMessage CONTAINS[c] "rsync"'
  run_cmd "unified-log-leak-filter" "$CASE_DIR/05_unified_logs/leak_relevant_${LOG_DAYS}d.json" \
    /usr/bin/log show --last "${LOG_DAYS}d" --style json --info --predicate "$LEAK_PREDICATE"
  run_cmd "unified-log-leak-compact" "$CASE_DIR/05_unified_logs/leak_relevant_${LOG_DAYS}d.compact.txt" \
    /usr/bin/log show --last "${LOG_DAYS}d" --style compact --info --predicate "$LEAK_PREDICATE"
else
  record_error "El comando log no está disponible"
fi

# 6. Spotlight/Quarantine quick inventories.
run_cmd "spotlight-wherefroms" "$CASE_DIR/08_reports/spotlight_wherefroms.txt" \
  /usr/bin/mdfind 'kMDItemWhereFroms == "*"c'
run_cmd "spotlight-archives" "$CASE_DIR/08_reports/spotlight_archives.txt" \
  /usr/bin/mdfind 'kMDItemFSName == "*.zip"c || kMDItemFSName == "*.7z"c || kMDItemFSName == "*.rar"c || kMDItemFSName == "*.tar"c || kMDItemFSName == "*.dmg"c'

# 7. Per-user artifact acquisition.
for home in /Users/*; do
  [ -d "$home" ] || continue
  collect_user_artifacts "$home"
done
collect_user_artifacts "/var/root"

# 8. FSEvents are central to reconstructing file activity. Collect the startup volume
# and any mounted volume except the destination evidence volume.
copy_path "/.fseventsd" "fsevents-startup-volume"
for mounted_volume in /Volumes/*; do
  [ -d "$mounted_volume" ] || continue
  mounted_device="$(df "$mounted_volume" 2>/dev/null | awk 'NR==2 {print $1}')"
  [ -n "$mounted_device" ] || continue
  if [ "$mounted_device" = "$DEST_DEVICE" ]; then
    log_event "SKIP destination volume metadata: $mounted_volume"
    continue
  fi
  copy_path "$mounted_volume/.fseventsd" "fsevents-mounted-volume"
  if [ "$DEEP_COLLECTION" -eq 1 ]; then
    copy_path "$mounted_volume/.Spotlight-V100" "spotlight-mounted-volume"
  fi
done

# Spotlight can be very large, so its raw store remains opt-in.
if [ "$DEEP_COLLECTION" -eq 1 ]; then
  copy_path "/.Spotlight-V100" "deep-spotlight"
fi

# 9. Automatic analysis before freezing logs and manifests.
log_event "COLLECTION_PHASE_COMPLETE analysis_enabled=$AUTO_ANALYZE"
if [ "$AUTO_ANALYZE" -eq 1 ]; then
  log_event "ANALYSIS_START"
  generate_analysis
  analysis_rc=$?
  if [ "$analysis_rc" -eq 0 ]; then
    log_event "ANALYSIS_OK report=08_reports/QK14_MacLeak_Timeline.html"
  else
    record_error "ANALYSIS_FAIL rc=$analysis_rc"
  fi
else
  log_event "ANALYSIS_SKIPPED by_operator"
fi

END_UTC="$(now_utc)"
printf 'end_utc=%s\n' "$END_UTC" >> "$CASE_META"

cat > "$CASE_DIR/00_case/README.txt" <<README
QK14 MacLeak Collector $VERSION

Resultado: $CASE_DIR
Inicio UTC: $START_UTC
Fin UTC: $END_UTC

Ficheros principales:
- 00_case/acquisition.log: acciones y errores con hora UTC.
- 08_reports/QK14_MacLeak_Timeline.html: informe HTML interactivo de actividad.
- 08_reports/timeline_activity.tsv: cronología normalizada completa.
- 08_reports/automatic_findings.tsv: indicadores automáticos de interés.
- 08_reports/undated_evidence.tsv: evidencias relevantes sin fecha normalizable.
- 09_manifests/SHA256SUMS.txt: SHA-256 de todos los ficheros adquiridos y generados.
- 09_manifests/manifest_sha256_timestamps.tsv: hashes, tamaños y fechas originales.
- 06_recent_inventory/recent_files.tsv: inventario de archivos recientes en zonas de interés.
- 05_unified_logs/: archivo de Unified Logs y filtrado orientado a fuga.
- 07_artifacts/filesystem/: copia de artefactos conservando la ruta original.

Limitaciones:
- Es una adquisición en vivo y modifica inevitablemente algunos registros.
- Full Disk Access debe estar concedido a Terminal/iTerm; sudo por sí solo puede no bastar.
- Las bases SQLite se copian junto a WAL/SHM, pero pueden cambiar durante la adquisición.
- Las conclusiones automáticas son indicadores y requieren validación pericial.
- FSEvents, Spotlight, audit logs y formatos propietarios se preservan, pero algunos requieren parsers especializados.
- No se copian claves privadas SSH, contraseñas ni cookies de navegador por defecto.
README

# From this point onward, do not append to acquisition.log or errors.log:
# their hashes must remain stable. Manifest errors go to a separate file.
trap - INT TERM HUP
MANIFEST_ERROR_LOG="$MANIFEST_DIR/manifest_generation_errors.log"
: > "$MANIFEST_ERROR_LOG"

SHA_FILE="$MANIFEST_DIR/SHA256SUMS.txt"
MANIFEST_TSV="$MANIFEST_DIR/manifest_sha256_timestamps.tsv"
: > "$SHA_FILE"
printf 'sha256\tsize_bytes\tsource_birth_time\tsource_modified_time\tsource_changed_time\tsource_accessed_time\tcollected_modified_time\toriginal_or_generated_path\tcollected_relative_path\n' > "$MANIFEST_TSV"

while IFS= read -r -d '' file; do
  rel="${file#$CASE_DIR/}"
  sha="$(/usr/bin/shasum -a 256 "$file" 2>>"$MANIFEST_ERROR_LOG" | awk '{print $1}')"
  [ -n "$sha" ] || sha="HASH_ERROR"
  size="$(/usr/bin/stat -f '%z' "$file" 2>/dev/null || printf '0')"
  collected_modified="$(stat_time m "$file")"

  case "$rel" in
    07_artifacts/filesystem/*)
      original="/${rel#07_artifacts/filesystem/}"
      if [ -e "$original" ] || [ -L "$original" ]; then
        source_for_times="$original"
      else
        source_for_times="$file"
      fi
      ;;
    *)
      original="generated:$rel"
      source_for_times="$file"
      ;;
  esac

  birth="$(stat_time B "$source_for_times")"
  modified="$(stat_time m "$source_for_times")"
  changed="$(stat_time c "$source_for_times")"
  accessed="$(stat_time a "$source_for_times")"

  printf '%s  %s\n' "$sha" "$rel" >> "$SHA_FILE"
  {
    sanitize_tsv "$sha"; printf '\t'
    sanitize_tsv "$size"; printf '\t'
    sanitize_tsv "$birth"; printf '\t'
    sanitize_tsv "$modified"; printf '\t'
    sanitize_tsv "$changed"; printf '\t'
    sanitize_tsv "$accessed"; printf '\t'
    sanitize_tsv "$collected_modified"; printf '\t'
    sanitize_tsv "$original"; printf '\t'
    sanitize_tsv "$rel"; printf '\n'
  } >> "$MANIFEST_TSV"
done < <(find "$CASE_DIR" -type f ! -path "$MANIFEST_DIR/*" -print0)

# Hash the principal manifests and immutable acquisition records.
SELF_HASHES="$MANIFEST_DIR/manifest_control_sha256.txt"
: > "$SELF_HASHES"
for control_file in "$SHA_FILE" "$MANIFEST_TSV" "$ACQ_LOG" "$ERROR_LOG" "$CASE_META" "$CASE_DIR/00_case/README.txt" "$CASE_DIR/10_collector/$(basename "$COLLECTOR_PATH")"; do
  [ -f "$control_file" ] || continue
  /usr/bin/shasum -a 256 "$control_file" >> "$SELF_HASHES" 2>>"$MANIFEST_ERROR_LOG"
done

printf '\nAdquisición finalizada.\n'
printf 'Resultado: %s\n' "$CASE_DIR"
printf 'Manifiesto: %s\n' "$MANIFEST_TSV"
printf 'Hashes: %s\n' "$SHA_FILE"
printf 'Errores: %s\n' "$ERROR_LOG"
if [ "$AUTO_ANALYZE" -eq 1 ]; then
  printf 'Informe HTML: %s\n' "$CASE_DIR/08_reports/QK14_MacLeak_Timeline.html"
  printf 'Timeline TSV: %s\n' "$CASE_DIR/08_reports/timeline_activity.tsv"
fi
exit 0
