#!/usr/bin/env bash
# =============================================================================
# scripts/update-filters.sh - Build AdGuard DNS filter lists (Syntax: AdGuard)
# Vị trí: scripts/update-filters.sh (gốc repo/scripts/), gọi từ workflow bằng
#   bash scripts/update-filters.sh   (chạy từ GỐC repo để file .txt ghi ra gốc repo)
#
# Luồng chạy:
#   1. Tải TẤT CẢ nguồn song song (1 lần curl, có retry).
#   2. Normalize từng nguồn -> dòng có tiền tố:
#        DOMAIN|<rule>  rule domain thuần (||d^, |d^, @@||d^, @@|d^)  -> kiểm tra DNS
#        RAW|<rule>     rule nâng cao (modifier, regex, wildcard, neo |) -> giữ nguyên
#   3. So MD5 với header của file đã commit -> list nào không đổi thì bỏ qua hẳn.
#   4. Gom domain của MỌI list cần cập nhật -> resolve MỘT lần (massdns) + cache TTL.
#      Chỉ loại domain khi NXDOMAIN được xác nhận bởi 2 nhóm resolver khác nhau.
#   5. Lọc, loại rule thừa (subdomain đã được ||parent^ phủ), ghi list.
#
# Biến môi trường: FORCE_UPDATE=true|false, GITHUB_REPOSITORY, GITHUB_EVENT_NAME
# =============================================================================
set -Eeuo pipefail
export LC_ALL=C

FORCE_UPDATE="${FORCE_UPDATE:-false}"
GITHUB_REPOSITORY="${GITHUB_REPOSITORY:-bibicadotnet/lists}"
EVENT_NAME="${GITHUB_EVENT_NAME:-manual}"
CACHE_DIR="${DNS_CACHE_DIR:-$HOME/.dnscache}"

BLOCK_OUT="blocklists.txt"
WHITE_OUT="whitelist.txt"

# --- Tham số tinh chỉnh ------------------------------------------------------
TTL_VALID=$((7 * 86400))   # domain resolve được: kiểm tra lại sau 7 ngày
TTL_DEAD=$((1 * 86400))    # domain NXDOMAIN: kiểm tra lại sau 1 ngày (phòng domain sống lại)
TTL_UNKNOWN=$((1 * 86400)) # không có kết luận (timeout/SERVFAIL): giữ rule, thử lại sau 1 ngày
RATE_A=500                 # số truy vấn đồng thời, nhóm resolver A
RATE_B=300                 # số truy vấn đồng thời, nhóm resolver B (xác nhận)
MIN_ANSWER_PCT=70          # < 70% domain có phản hồi rõ ràng => coi như DNS lỗi, không ghi gì
MAX_SHRINK_PCT=30          # list mới nhỏ hơn bản cũ > 30% => giữ bản cũ (trừ khi FORCE_UPDATE)

VERSION="$(date -u +%Y.%m.%d.%H%M)"
LAST_MODIFIED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
HZ="https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock"

# --- Nguồn của blocklists.txt / whitelist.txt (gộp) --------------------------
MERGED_SOURCES=(
  "block1|https://adguardteam.github.io/HostlistsRegistry/assets/filter_16.txt"
  "block2|https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"
  "block3|https://raw.githubusercontent.com/bibicadotnet/AdGuard-Home-blocklists/refs/heads/main/byme.txt"
  "block4|https://badmojr.github.io/1Hosts/Lite/adblock.txt"
  "white1|https://raw.githubusercontent.com/bibicadotnet/AdGuard-Home-blocklists/main/whitelist.txt"
  "white2|https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Whitelists/Whitelist"
)

# --- Các list đơn lẻ: "file_out|url|title|description" -----------------------
REMOTE_LISTS=(
  "hagezi_light.txt|$HZ/light.txt|HaGeZi Multi LIGHT: Basic protection (ads, trackers, telemetry)|Lightweight list that blocks ads, trackers, metrics, telemetry and some badware with minimal breakage. Best for weak devices or when no admin is around to unblock things."
  "hagezi_multi.txt|$HZ/multi.txt|HaGeZi Multi NORMAL: All-round protection|Balanced list that blocks ads, trackers, telemetry, phishing, malware, scams, fakes and cryptojacking. Rarely causes breakage."
  "hagezi_pro.txt|$HZ/pro.txt|HaGeZi Multi PRO: Extended protection (recommended)|Larger list that blocks ads, trackers, telemetry, phishing, malware, scams, fakes and cryptojacking. Good balance of coverage and few false positives."
  "hagezi_pro_plus.txt|$HZ/pro.plus.txt|HaGeZi Multi PRO++: Advanced protection (more aggressive)|More aggressive than PRO against ads, trackers, telemetry, phishing, malware, scams and cryptojacking. May block a few legitimate domains, for experienced users."
  "hagezi_ultimate.txt|$HZ/ultimate.txt|HaGeZi Multi ULTIMATE: Maximum protection (most aggressive)|Strictest HaGeZi multi list. Blocks ads, trackers, telemetry, phishing, malware, scams and more, including popular trackers. Can break some apps or websites, only use it if you know how to whitelist."
  "hagezi_tif_medium.txt|$HZ/tif.medium.txt|HaGeZi Threat Intelligence Feeds (Medium): Malware and phishing protection|Medium-sized threat intelligence list built from the most important feeds. Targets malware, phishing, scam and other threat domains, not general ads."
  "hagezi_nsfw.txt|$HZ/nsfw.txt|HaGeZi NSFW: Adult content blocker|Blocks adult (NSFW) content domains. Does not block ads or trackers."
  "stevenblack_unified.txt|https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts|StevenBlack Unified Hosts: Adware and malware|Unified hosts file from StevenBlack, merged from reputable ad, tracker and malware sources. Hosts entries are kept as exact-match rules (|domain^), so subdomains are not blocked."
  "velesila_yhosts.txt|https://raw.githubusercontent.com/VeleSila/yhosts/master/hosts|VeleSila yhosts: Chinese ads, trackers and malware|Hosts file maintained by VeleSila that blocks Chinese ads, trackers, telemetry and malicious domains. Hosts entries are kept as exact-match rules (|domain^), so subdomains are not blocked."
  "oisd_big.txt|https://big.oisd.nl|OISD Big: Ads, trackers, phishing and malware|Large, actively maintained list that blocks ads, trackers, phishing, malware and scam domains while aiming to avoid false positives."
  "oisd_nsfw.txt|https://nsfw.oisd.nl|OISD NSFW: Adult content blocker|OISD list that blocks adult (NSFW) content domains. Does not block ads or trackers."
)

MERGED_BLOCK_TITLE="Blocklist (ABPVN + AdGuard DNS + 1Hosts Lite)"
MERGED_BLOCK_DESC="Ads, trackers and malware domains merged from AdGuard DNS filter, ABPVN (Vietnamese ads), 1Hosts Lite and bibicadotnet's custom list (CocCoc, MSN, DNS canary). Hosts-style entries are kept as exact-match rules (|domain^)."
MERGED_WHITE_TITLE="Whitelist (ShadowWhisperer)"
MERGED_WHITE_DESC="Exception rules that prevent false positives. Merged from bibicadotnet's manual allowlist, ShadowWhisperer's whitelist and the @@ exceptions found in the source blocklists. Use together with blocklists.txt."

# =============================================================================
# Tiện ích
# =============================================================================
warn() { echo "::warning::$*"; }

human_size() {
  awk -v b="$1" 'BEGIN { if (b >= 1048576) printf "%.2f MB", b/1048576; else printf "%.1f KB", b/1024 }'
}

# header_value <file> <key>  ->  giá trị của dòng "! <key>: ..."
header_value() {
  sed -n "/^! $2: /{s/^! $2: //;p;q;}" "$1"
}

# =============================================================================
# AWK: normalize + loại rule thừa (ghi ra $WORK để tránh quote phức tạp)
# =============================================================================
write_awk_scripts() {
  cat > "$WORK/normalize.awk" <<'AWK'
# normalize.awk  -v force_allow=0|1
function trim(s) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); return s }
function is_domain(d) {
  return (length(d) <= 253 && d ~ /^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)+$/)
}
function is_label(d) { return (d ~ /^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?$/) }
function emit(tag, rule,    o) { o = tag "|" rule; if (!seen[o]++) print o }

# Chỉ giữ modifier mà AdGuard DNS / AdGuard Home hỗ trợ.
# (ctag chỉ có trong AdGuard Home; respgeo: chưa xác minh được trong tài liệu - xoá nếu không cần)
function valid_dns_modifiers(mod_str,    n, arr, i, m, key) {
  if (mod_str == "") return 0
  gsub(/\\,/, "\001", mod_str)            # dấu phẩy được escape không phải dấu tách
  n = split(mod_str, arr, ",")
  for (i = 1; i <= n; i++) {
    m = trim(arr[i])
    if (m == "") return 0
    key = m; sub(/=.*/, "", key)
    if (key !~ /^(client|denyallow|dnstype|dnsrewrite|important|badfilter|ctag|respgeo)$/) return 0
  }
  return 1
}

{
  raw = trim($0)
  if (raw == "" || raw ~ /^[!#;\[]/) next
  if (raw ~ /#(@|\$|\?|%)*#/) next        # rule cosmetic của trình duyệt (##, #@#, #?#, #$#...)

  # 1. Regex: /re/, @@/re/, /re/$modifiers  (xử lý trước khi cắt comment vì regex có thể chứa #)
  if (raw ~ /^(@@)?\/.*\/(\$[^[:space:]]*)?$/) {
    if (raw ~ /\/\$/) {
      mod_part = raw; sub(/^.*\/\$/, "", mod_part)
      if (!valid_dns_modifiers(mod_part)) next
    }
    if (force_allow == 1 && raw !~ /^@@/) raw = "@@" raw
    emit("RAW", raw); next
  }

  # Cắt comment cuối dòng TRƯỚC khi xét modifier ($ trong comment không còn làm hỏng rule)
  sub(/[[:space:]]+#.*$/, "", raw); raw = trim(raw)
  if (raw == "") next

  # 2. Rule có modifier ($), kể cả rule bắt đầu bằng $ như $dnstype=...
  if (raw ~ /\$/) {
    idx = index(raw, "$")
    pat_part = substr(raw, 1, idx - 1)
    mod_part = substr(raw, idx + 1)
    if (!valid_dns_modifiers(mod_part)) next
    if (pat_part ~ /\//) next
    pat_lc = tolower(pat_part)             # domain không phân biệt hoa/thường; modifier giữ nguyên
    raw = pat_lc "$" mod_part
    if (force_allow == 1 && pat_part != "" && raw !~ /^@@/) raw = "@@" raw
    emit("RAW", raw); next
  }

  # 3. Wildcard (*), neo cuối (|), hoặc neo đầu không có ^  -> giữ nguyên
  if (raw ~ /\*/ || raw ~ /\|$/ || (raw ~ /^(@@)?\|/ && raw !~ /\^/)) {
    if (raw ~ /\//) next                   # có path URL => không phải rule DNS
    raw = tolower(raw)
    if (force_allow == 1 && raw !~ /^@@/) raw = "@@" raw
    emit("RAW", raw); next
  }

  # 4. Dòng kiểu /etc/hosts (nhiều alias trên 1 dòng) -> |domain^ (khớp chính xác)
  line = tolower(raw)
  if (line ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[[:space:]]+/ || line ~ /^[0-9a-f:]+:[0-9a-f:]+[[:space:]]+/) {
    n = split(line, fields, /[[:space:]]+/)
    for (i = 2; i <= n; i++) {
      d = fields[i]
      if (d ~ /^[0-9.]+$/ || d == "localhost.localdomain") continue
      if (is_domain(d)) emit("DOMAIN", (force_allow ? "@@" : "") "|" d "^")
    }
    next
  }

  # 5. Rule domain thuần: ||d^, |d^, @@||d^, domain
  allow = force_allow
  if (line ~ /^@@/) { allow = 1; sub(/^@@/, "", line) }
  exact = 0; anch = 0
  if (line ~ /^\|\|/)    { sub(/^\|\|/, "", line); anch = 1 }
  else if (line ~ /^\|/) { sub(/^\|/, "", line); exact = 1; anch = 1 }

  sub(/\^.*/, "", line); sub(/[!].*/, "", line)
  if (line ~ /\//) next
  sub(/:.*/, "", line); line = trim(line)
  if (line ~ /^[0-9.]+$/) next

  if (is_domain(line)) {
    emit("DOMAIN", (allow ? "@@" : "") (exact ? "|" : "||") line "^")
  } else if (anch && is_label(line)) {
    # rule cấp TLD (vd ||xyz^): giữ nguyên, không cần resolve
    emit("RAW", (allow ? "@@" : "") (exact ? "|" : "||") line "^")
  }
}
AWK

  cat > "$WORK/final_dedup.awk" <<'AWK'
# final_dedup.awk <file> <file>   (đọc cùng 1 file 2 lần)
# - bỏ |d^ nếu đã có ||d^ cùng loại (chặn / cho phép)
# - bỏ rule của subdomain nếu một domain cha đã có ||cha^ cùng loại
function parse(r,    s) {
  if (r !~ /^DOMAIN\|/) return 0
  s = substr(r, 8)
  P_cls = "B"
  if (substr(s, 1, 2) == "@@") { P_cls = "W"; s = substr(s, 3) }
  if (substr(s, 1, 2) == "||") { P_wild = 1; s = substr(s, 3) } else { P_wild = 0; s = substr(s, 2) }
  sub(/\^$/, "", s); P_dom = s
  return 1
}
NR == FNR { if (parse($0) && P_wild) wild[P_cls, P_dom] = 1; next }
{
  if (!parse($0)) { if (!seen[$0]++) print; next }
  cls = P_cls; dom = P_dom; isw = P_wild
  if (!isw && ((cls, dom) in wild)) next
  p = dom; red = 0
  while ((i = index(p, ".")) > 0) {
    p = substr(p, i + 1)
    if (index(p, ".") == 0) break
    if ((cls, p) in wild) { red = 1; break }
  }
  if (!red && !seen[$0]++) print
}
AWK
}

normalize() { awk -v force_allow="${1:-0}" -f "$WORK/normalize.awk"; }

# =============================================================================
# Tải nguồn
# =============================================================================
download_all() {
  local cfg="$WORK/curl.cfg" spec name url out
  : > "$cfg"
  for spec in "${MERGED_SOURCES[@]}"; do
    name="${spec%%|*}"; url="${spec#*|}"
    printf 'url = "%s"\noutput = "%s/%s.txt"\n' "$url" "$DL" "$name" >> "$cfg"
  done
  for spec in "${REMOTE_LISTS[@]}"; do
    out="${spec%%|*}"; url="$(cut -d'|' -f2 <<< "$spec")"
    printf 'url = "%s"\noutput = "%s/remote_%s"\n' "$url" "$DL" "$out" >> "$cfg"
  done
  echo "Đang tải $(grep -c '^url' "$cfg") nguồn (song song)..."
  curl --config "$cfg" --silent --show-error --location --fail --parallel --parallel-max 8 \
       --retry 3 --retry-delay 3 --retry-all-errors --max-time 180 --remove-on-error || \
    warn "Một số nguồn tải lỗi, list tương ứng sẽ được giữ nguyên bản cũ"
}

# =============================================================================
# Hàng đợi xử lý
# =============================================================================
PENDING_N=0

# prepare <tagged_file> <out> <title> <desc> <url|->
# So MD5 với header; nếu đổi (hoặc bị ép) thì đưa vào hàng đợi.
prepare() {
  local tagged="$1" out="$2" title="$3" desc="$4" url="${5:--}"
  local md5 old=""
  if [[ ! -s "$tagged" ]]; then
    warn "$out: nguồn không có rule hợp lệ nào, giữ nguyên file cũ"
    return 0
  fi
  md5="$(md5sum "$tagged" | awk '{print $1}')"
  [[ -f "$out" ]] && old="$(header_value "$out" "Source MD5")"
  if [[ "$SKIP_MD5" != 1 && "$md5" == "$old" ]]; then
    echo "= $out: nguồn không đổi, bỏ qua"
    return 0
  fi
  PENDING_N=$((PENDING_N + 1))
  cp "$tagged" "$WORK/pending/$PENDING_N.rules"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$out" "$md5" "$WORK/pending/$PENDING_N.rules" "$url" "$title" "$desc" \
    >> "$WORK/pending.tsv"
  echo "+ $out: đưa vào hàng đợi ($(wc -l < "$tagged") rules)"
}

prepare_merged() {
  local n ok=1
  for n in block1 block2 block3 block4 white1 white2; do
    [[ -s "$DL/$n.txt" ]] || { warn "thiếu nguồn $n"; ok=0; }
  done
  if [[ "$ok" != 1 ]]; then
    warn "Bỏ qua $BLOCK_OUT và $WHITE_OUT lần này (thiếu nguồn, tránh làm list bị hụt)"
    return 0
  fi
  # Normalize từng file riêng: white* => toàn bộ là whitelist; block* => dòng @@ là whitelist
  {
    for n in white1 white2; do normalize 1 < "$DL/$n.txt"; done
    for n in block1 block2 block3 block4; do normalize 0 < "$DL/$n.txt"; done
  } | sort -u > "$WORK/all_rules.txt"

  { grep -E  '^(DOMAIN|RAW)\|@@' "$WORK/all_rules.txt" || true; } > "$WORK/white_rules.txt"
  { grep -vE '^(DOMAIN|RAW)\|@@' "$WORK/all_rules.txt" || true; } > "$WORK/block_rules.txt"

  prepare "$WORK/white_rules.txt" "$WHITE_OUT" "$MERGED_WHITE_TITLE" "$MERGED_WHITE_DESC" "-"
  prepare "$WORK/block_rules.txt" "$BLOCK_OUT" "$MERGED_BLOCK_TITLE" "$MERGED_BLOCK_DESC" "-"
}

prepare_remote() {
  local spec out url title desc rest f
  for spec in "${REMOTE_LISTS[@]}"; do
    out="${spec%%|*}"; rest="${spec#*|}"
    url="${rest%%|*}"; rest="${rest#*|}"
    title="${rest%%|*}"; desc="${rest#*|}"
    f="$DL/remote_$out"
    if [[ ! -s "$f" ]]; then
      warn "$out: không tải được $url, giữ nguyên file cũ"
      continue
    fi
    normalize 0 < "$f" | sort -u > "$WORK/remote.rules"
    prepare "$WORK/remote.rules" "$out" "$title" "$desc" "$url"
  done
}

# =============================================================================
# DNS: resolve 1 lần cho mọi list, có cache TTL
# =============================================================================
# run_massdns <resolvers_file> <domains_file> <rate>  ->  "domain STATUS" (mọi phản hồi)
run_massdns() {
  massdns -r "$1" -t A -o J -s "$3" --retry SERVFAIL "$2" 2>/dev/null \
    | jq -r '"\(.name | rtrimstr(".") | ascii_downcase) \(.status)"' 2>/dev/null || true
}

# Canary: domain chắc chắn sống phải NOERROR, domain .invalid phải NXDOMAIN
dns_healthy() {
  local res good bad
  printf '%s\n' google.com cloudflare.com github.com > "$WORK/canary_good.txt"
  bad="nxd-canary-$RANDOM$RANDOM.invalid"
  printf '%s\n' "$bad" > "$WORK/canary_bad.txt"
  for res in "$WORK/resolvers_a.txt" "$WORK/resolvers_b.txt"; do
    run_massdns "$res" "$WORK/canary_good.txt" 10 > "$WORK/canary_good.res"
    run_massdns "$res" "$WORK/canary_bad.txt"  10 > "$WORK/canary_bad.res"
    good="$(grep -c ' NOERROR$' "$WORK/canary_good.res" || true)"
    if [[ "$good" -lt 2 ]] || ! grep -q ' NXDOMAIN$' "$WORK/canary_bad.res"; then
      warn "Canary DNS thất bại ($(basename "$res")): good=$good/3. Bỏ qua cập nhật lần này."
      return 1
    fi
  done
}

resolve_domains() {
  local now cache="$WORK/cache.tsv" keep="$WORK/cache_keep.tsv" need="$WORK/need.txt"
  now="$(date +%s)"
  printf '%s\n' 8.8.8.8 8.8.4.4 > "$WORK/resolvers_a.txt"
  printf '%s\n' 1.1.1.1 1.0.0.1 > "$WORK/resolvers_b.txt"   # không dùng Quad9: nó tự chặn domain độc hại bằng NXDOMAIN

  # Gom domain của tất cả list đang chờ
  { cat "$WORK"/pending/*.rules | grep '^DOMAIN|' || true; } \
    | sed -E 's/^DOMAIN\|(@@)?\|\|?//; s/\^$//' | sort -u > "$WORK/domains.txt"
  echo "Tổng domain cần kiểm tra (đã gộp mọi list): $(wc -l < "$WORK/domains.txt")"

  # Nạp cache
  : > "$cache"
  if [[ -f "$CACHE_DIR/cache.tsv.gz" ]]; then
    gzip -dc "$CACHE_DIR/cache.tsv.gz" > "$cache" 2>/dev/null || : > "$cache"
  fi

  # Tách: entry còn hạn -> $keep ; domain chưa có / hết hạn -> $need
  : > "$keep"
  awk -v now="$now" -v tv="$TTL_VALID" -v td="$TTL_DEAD" -v tu="$TTL_UNKNOWN" -v keepf="$keep" '
    FILENAME == ARGV[1] {
      ttl = ($2 == "V") ? tv : (($2 == "D") ? td : tu)
      if (now - $3 < ttl) { fresh[$1] = 1; print $0 > keepf }
      next
    }
    !($1 in fresh) { print $1 }
  ' "$cache" "$WORK/domains.txt" > "$need"
  local need_n; need_n="$(wc -l < "$need")"
  echo "Cache hit: $(( $(wc -l < "$WORK/domains.txt") - need_n )) | cần resolve mới: $need_n"

  cp "$keep" "$WORK/cache.new"
  if [[ "$need_n" -gt 0 ]]; then
    dns_healthy || return 1

    # Pass 1: nhóm resolver A
    run_massdns "$WORK/resolvers_a.txt" "$need" "$RATE_A" > "$WORK/res1.txt"
    local answered
    answered="$(awk '$2 == "NOERROR" || $2 == "NXDOMAIN" { c++ } END { print c + 0 }' "$WORK/res1.txt")"
    echo "Pass 1: $answered / $need_n có phản hồi rõ ràng"
    if [[ "$need_n" -ge 500 && $(( answered * 100 )) -lt $(( need_n * MIN_ANSWER_PCT )) ]]; then
      warn "Chỉ $answered/$need_n domain có phản hồi (< ${MIN_ANSWER_PCT}%): nghi ngờ bị rate-limit. Không ghi gì lần này."
      return 1
    fi

    # Pass 2: xác nhận bằng nhóm resolver B cho mọi domain chưa NOERROR (NXDOMAIN / timeout / SERVFAIL)
    awk '
      FILENAME == ARGV[1] { if ($2 == "NOERROR") ok[$1] = 1; next }
      !($1 in ok) { print $1 }
    ' "$WORK/res1.txt" "$need" > "$WORK/retry.txt"
    : > "$WORK/res2.txt"
    if [[ -s "$WORK/retry.txt" ]]; then
      run_massdns "$WORK/resolvers_b.txt" "$WORK/retry.txt" "$RATE_B" > "$WORK/res2.txt"
      echo "Pass 2 (xác nhận): $(wc -l < "$WORK/retry.txt") domain"
    fi

    # Kết luận: V = có ở ít nhất 1 nhóm | D = NXDOMAIN ở CẢ HAI nhóm | U = còn lại (giữ rule)
    awk -v now="$now" '
      function pick(arr, k) { return (k in arr) ? arr[k] : "" }
      FILENAME == ARGV[1] { if (!($1 in r1) || r1[$1] !~ /^(NOERROR|NXDOMAIN)$/) r1[$1] = $2; next }
      FILENAME == ARGV[2] { if (!($1 in r2) || r2[$1] !~ /^(NOERROR|NXDOMAIN)$/) r2[$1] = $2; next }
      {
        a = pick(r1, $1); b = pick(r2, $1)
        if (a == "NOERROR" || b == "NOERROR") s = "V"
        else if (a == "NXDOMAIN" && b == "NXDOMAIN") s = "D"
        else s = "U"
        print $1, s, now
      }
    ' "$WORK/res1.txt" "$WORK/res2.txt" "$need" >> "$WORK/cache.new"
    echo "Kết quả mới: V=$(awk '$2=="V"' "$WORK/cache.new" | wc -l) D=$(awk '$2=="D"' "$WORK/cache.new" | wc -l) (cộng dồn cache)"
  fi

  # Lưu cache (chỉ là tối ưu tốc độ, mất cache không ảnh hưởng tính đúng)
  mkdir -p "$CACHE_DIR"
  gzip -6 -c "$WORK/cache.new" > "$CACHE_DIR/cache.tsv.gz"

  awk '$2 == "D" { print $1 }' "$WORK/cache.new" > "$WORK/dead.txt"
  echo "#sentinel#" >> "$WORK/dead.txt"
}

# =============================================================================
# Ghi list
# =============================================================================
# write_list <out> <title> <desc> <body> <md5> <url|->
write_list() {
  local out="$1" title="$2" desc="$3" body="$4" md5="$5" url="${6:--}"
  local entries old_entries size_label="0 KB" new_label i
  entries="$(wc -l < "$body")"

  if [[ -f "$out" ]]; then
    old_entries="$(header_value "$out" "Number of entries")"; old_entries="${old_entries:-0}"
    if [[ "$FORCE_UPDATE" != true && "$old_entries" -ge 1000 ]] \
       && (( entries * 100 < old_entries * (100 - MAX_SHRINK_PCT) )); then
      warn "$out: số rule giảm bất thường ($old_entries -> $entries), giữ nguyên bản cũ"
      return 0
    fi
    if [[ "$FORCE_UPDATE" != true ]] \
       && grep -v -e '^!' -e '^\[Adblock' "$out" | cmp -s - "$body"; then
      # Body không đổi nhưng MD5 nguồn đổi: cập nhật MD5 để lần sau không phải chạy lại
      sed -i "s/^! Source MD5: .*/! Source MD5: $md5/" "$out"
      echo "= $out: kết quả không đổi (đã đồng bộ Source MD5)"
      return 0
    fi
  fi

  # Header chứa dung lượng file -> ghi lại vài lần cho tới khi con số ổn định
  for i in 1 2 3 4; do
    {
      echo "[Adblock Plus 2.0]"
      echo "! Title: $title"
      echo "! Description: $desc Unresolvable domains removed (checked via massdns)."
      echo "! Version: $VERSION"
      echo "! Last modified: $LAST_MODIFIED"
      echo "! Expires: 12 hours (update frequency)"
      if [[ "$url" != "-" ]]; then echo "! Source: $url"; fi
      echo "! Source MD5: $md5"
      echo "! GitHub: https://github.com/$GITHUB_REPOSITORY"
      echo "! Homepage: https://lists.bibica.net/$out"
      echo "! Syntax: AdGuard"
      echo "! Number of entries: $entries"
      echo "! Size: $size_label"
      echo "!"
      cat "$body"
    } > "$out"
    new_label="$(human_size "$(wc -c < "$out")")"
    if [[ "$new_label" == "$size_label" ]]; then break; fi
    size_label="$new_label"
  done
  echo "✔ $out: đã cập nhật ($entries entries, $size_label)"
}

finalize_pending() {
  local out md5 file url title desc
  while IFS=$'\t' read -r out md5 file url title desc; do
    # 1. Bỏ domain đã xác nhận chết (RAW luôn giữ)
    awk '
      FILENAME == ARGV[1] { dead[$1] = 1; next }
      /^RAW\|/ { print; next }
      { d = $0; sub(/^DOMAIN\|(@@)?\|\|?/, "", d); sub(/\^$/, "", d); if (!(d in dead)) print }
    ' "$WORK/dead.txt" "$file" > "$WORK/filtered.rules"

    # 2. Loại rule thừa, bỏ tiền tố, sắp xếp
    awk -f "$WORK/final_dedup.awk" "$WORK/filtered.rules" "$WORK/filtered.rules" \
      | sed -E 's/^(DOMAIN|RAW)\|//' | sort -u > "$WORK/body.rules"

    if [[ ! -s "$WORK/body.rules" ]]; then
      warn "$out: sau khi lọc không còn rule nào, giữ nguyên file cũ"
      continue
    fi
    echo "$out: $(wc -l < "$file") rules gốc -> $(wc -l < "$WORK/body.rules") sau khi lọc DNS + loại rule thừa"
    write_list "$out" "$title" "$desc" "$WORK/body.rules" "$md5" "$url"
  done < "$WORK/pending.tsv"
}

# =============================================================================
main() {
  WORK="$(mktemp -d)"
  trap 'rm -rf "$WORK"' EXIT
  DL="$WORK/dl"
  mkdir -p "$DL" "$WORK/pending"
  : > "$WORK/pending.tsv"
  write_awk_scripts

  # SKIP_MD5=1: xử lý lại mọi list dù nguồn không đổi
  #   - FORCE_UPDATE=true (chạy tay)
  #   - lượt chạy đầu mỗi ngày (~00:00 UTC) để kiểm tra lại domain chết có sống lại không
  SKIP_MD5=0
  local hour_utc=$((10#$(date -u +%H)))
  if [[ "$FORCE_UPDATE" == true ]]; then
    SKIP_MD5=1; echo "Chế độ: FORCE_UPDATE"
  elif [[ "$EVENT_NAME" == schedule && "$hour_utc" -le 1 ]]; then
    SKIP_MD5=1; echo "Chế độ: kiểm tra lại toàn bộ hằng ngày"
  fi

  download_all
  prepare_merged
  prepare_remote

  if [[ ! -s "$WORK/pending.tsv" ]]; then
    echo "Không có list nào cần cập nhật."
    return 0
  fi

  if ! resolve_domains; then
    warn "Bỏ qua ghi list lần này do DNS không đáng tin; các file hiện tại được giữ nguyên."
    return 0
  fi
  finalize_pending
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
