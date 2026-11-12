# AdGuard Filters

- Blocklist và whitelist dạng `||domain^` / `@@||domain^`, dùng cho AdGuard Home và các công cụ chặn quảng cáo hỗ trợ cú pháp AdGuard. 
- Tự động cập nhật mỗi giờ.
- Các url chạy qua cache từ Cloudflare, tốc độ sẽ ổn định hơn so với `raw.githubusercontent.com` truyền thống

## 1. Bộ lọc khuyên dùng

**Blocklist**

- Bao gồm các bộ lọc: [ABPVN List (Việt Nam)](https://adguardteam.github.io/HostlistsRegistry/assets/filter_16.txt) + [AdGuard DNS filter](https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt) + [1Hosts (Lite)](https://badmojr.github.io/1Hosts/Lite/adblock.txt) + danh sách [bổ sung](https://raw.githubusercontent.com/bibicadotnet/AdGuard-Home-blocklists/refs/heads/main/byme.txt) riêng, đủ cho 99% các nhu cầu chặn quảng cáo tại Việt Nam.

```
https://lists.bibica.net/blocklists.txt
```

**Whitelist**

- Bao gồm danh sách [bổ sung riêng](https://raw.githubusercontent.com/bibicadotnet/AdGuard-Home-blocklists/main/whitelist.txt) và [ShadowWhisperer](https://github.com/ShadowWhisperer/BlockLists), giúp tránh chặn nhầm các dịch vụ phổ biến.

```
https://lists.bibica.net/whitelist.txt
```

---

### 2. Các Bộ Lọc thông dụng (đã làm sạch domain lỗi thời)

Không đề xuất dùng, user tại Việt Nam, dùng danh sách blocklist, whitelist đề xuất ở trên là đủ, các bộ lọc bên dưới chặn các domain quốc tế, đôi lúc chặn quá mức cần thiết, gây ra tình huống chặn nhầm


**HaGeZi Light**
> Phiên bản nhẹ nhất, chặn quảng cáo và theo dõi cơ bản. Tiêu chí "Zero breakage" (gần như không gây lỗi trang web). Phù hợp cho thiết bị yếu hoặc người không muốn phải cấu hình whitelist nhiều.
```
https://lists.bibica.net/hagezi_light.txt
```

**HaGeZi Multi (Normal)**
> Phiên bản tiêu chuẩn và phổ biến nhất của HaGeZi. Cân bằng hoàn hảo giữa việc chặn quảng cáo/theo dõi hiệu quả và tránh làm hỏng các trang web thông thường.
```
https://lists.bibica.net/hagezi_multi.txt
```

**HaGeZi Pro**
> Chặn mạnh tay hơn bản Normal, loại bỏ thêm nhiều trình theo dõi ẩn và quảng cáo cứng đầu. Tỉ lệ lỗi web thấp nhưng đôi khi sẽ cần bạn tự mở khóa (whitelist) một số dịch vụ.
```
https://lists.bibica.net/hagezi_pro.txt
```

**HaGeZi Pro++**
> Phiên bản nâng cao của Pro, nhắm vào các máy chủ thu thập dữ liệu người dùng (telemetry) cực kỳ gắt gao. Phù hợp với người dùng có kinh nghiệm xử lý lỗi web.
```
https://lists.bibica.net/hagezi_pro_plus.txt
```

**HaGeZi Ultimate**
> Bộ lọc tối đa, chặn mọi thứ có thể (quảng cáo, tracker, telemetry). Chắc chắn sẽ gây lỗi hoặc chặn nhầm các dịch vụ hợp pháp, chỉ dành cho "Power users" sẵn sàng theo dõi log liên tục.
```
https://lists.bibica.net/hagezi_ultimate.txt
```

**HaGeZi Threat Intelligence (Medium)**
> Chuyên dùng để bảo mật. Ngăn chặn truy cập vào các tên miền độc hại, lừa đảo (phishing), phát tán mã độc (malware), và máy chủ điều khiển botnet.
```
https://lists.bibica.net/hagezi_tif_medium.txt
```

**HaGeZi NSFW**
> Chuyên dùng để chặn các trang web có nội dung người lớn, khiêu dâm. Thích hợp cho mạng gia đình có trẻ nhỏ.
```
https://lists.bibica.net/hagezi_nsfw.txt
```

**OISD Big**
> Bộ lọc siêu phổ biến với triết lý thiết kế "Không gây lỗi web". Chặn hiệu quả quảng cáo, phần mềm độc hại và tracker nhưng được kiểm duyệt kỹ lưỡng để không chặn nhầm các trang web thông thường.
```
https://lists.bibica.net/oisd_big.txt
```

**OISD NSFW**
> Bộ lọc chặn nội dung người lớn (khiêu dâm) dựa trên cơ sở dữ liệu chất lượng cao của OISD.
```
https://lists.bibica.net/oisd_nsfw.txt
```

**StevenBlack Unified Hosts**
> Bộ lọc "huyền thoại" lâu đời nhất, được gộp từ nhiều nguồn uy tín (như adaway, yoyo...). Chặn quảng cáo, phần mềm độc hại và các công cụ theo dõi một cách toàn diện.
```
https://lists.bibica.net/stevenblack_unified.txt
```

---

## Cách hoạt động & Công nghệ tối ưu

Mọi domain trong các bộ lọc ở trên, đều được kiểm tra lại, các domain "chết" ( trả về SERVFAIL/NXDOMAIN) sẽ bị lạoi bỏ, chỉ giữ lại các domain **còn đang hoạt động**. Điều này giúp danh sách gọn nhẹ đi đáng kể, không chứa domain chết, giảm tải bộ nhớ cho thiết bị mạng/AdGuard Home trong khi vẫn giữ nguyên sức mạnh chặn quảng cáo thực tế.

## Cách dùng với AdGuard Home

- Blocklist: Chọn **Filters → DNS blocklists → Add blocklist → Add a custom list**, dán link blocklist.
- Whitelist: Chọn **Filters → DNS allowlists → Add allowlist → Add a custom list**, dán link whitelist.
