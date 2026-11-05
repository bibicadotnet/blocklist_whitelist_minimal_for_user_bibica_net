# AdGuard Filters

Blocklist và whitelist dạng `||domain^` / `@@||domain^`, dùng cho AdGuard Home và các công cụ chặn quảng cáo hỗ trợ cú pháp AdGuard. Tự động cập nhật mỗi giờ.

## Link đăng ký

**Blocklist**

```
https://lists.bibica.net/blocklists.txt
```

**Whitelist**

```
https://lists.bibica.net/whitelist.txt
```

## Nội dung

**Blocklist** gộp các bộ lọc: ABPVN List (Việt Nam) + AdGuard DNS filter + 1Hosts (Lite) + danh sách bổ sung riêng. Đủ dùng cho nhu cầu chặn quảng cáo thông thường.

**Whitelist** gộp từ [bibicadotnet](https://github.com/bibicadotnet/AdGuard-Home-blocklists) và [ShadowWhisperer](https://github.com/ShadowWhisperer/BlockLists), giúp tránh chặn nhầm các dịch vụ phổ biến.

Mọi domain trong blocklist đều được kiểm tra DNS bằng [massdns](https://github.com/blechschmidt/massdns), chỉ giữ lại domain còn resolve được nên danh sách gọn, không chứa domain chết.

## Cách dùng với AdGuard Home

- Blocklist: **Filters → DNS blocklists → Add blocklist → Add a custom list**, dán link blocklist.
- Whitelist: **Filters → DNS allowlists → Add allowlist → Add a custom list**, dán link whitelist.
