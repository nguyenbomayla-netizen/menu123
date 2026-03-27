Cách dùng nhanh

1. Chép:
   - public/nova-customer.html
   - public/nova-customer-config.js
   vào repo web của bạn.

2. Deploy Cloudflare Worker bằng:
   - customer-worker/index.js

3. Set env cho worker:
   - SUPABASE_VERIFY_URL = URL rent-verify-key thật
   - NOVA_USERNAME = username account thuê
   - NOVA_USER_HMAC_SECRET = hmac_secret của account đó
   - NOVA_HMAC_HEADER = chỉ set nếu upstream yêu cầu
   - ALLOWED_ORIGINS = domain được phép gọi, ngăn bằng dấu phẩy

4. Nếu dùng URL worker khác, sửa file:
   - public/nova-customer-config.js

5. HTML này chỉ gửi:
   - key
   - device_id

   Worker sẽ tự thêm:
   - username
   - ts
   - sig_user

Không nhét secret vào HTML public.
