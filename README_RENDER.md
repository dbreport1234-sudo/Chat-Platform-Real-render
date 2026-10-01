# Chat Platform Real — Render Ready

ชุดนี้เตรียมสำหรับ Render Web Service โดยเฉพาะ

## Deploy จาก GitHub

1. Push ไฟล์ทั้งหมดในโฟลเดอร์นี้ขึ้น GitHub
2. Render → New → Web Service → เลือก repository
3. Runtime: Node
4. Build Command: `npm install`
5. Start Command: `npm start`
6. Health Check Path: `/api/health`

### สำคัญ
ไม่จำเป็นต้องตั้ง `JWT_SECRET` เองเพื่อให้ระบบเริ่มทำงานได้แล้ว
ถ้า Render ไม่มี `JWT_SECRET` ระบบจะสร้าง secret แบบสุ่มและเก็บไว้ใน `DATA_DIR/.jwt-secret` อัตโนมัติ

อย่างไรก็ตาม สำหรับ Production แนะนำให้ตั้ง Environment Variable เอง:

`JWT_SECRET` = random string อย่างน้อย 32 ตัวอักษร

## Render Blueprint

ไฟล์ `render.yaml` ใช้ได้กับ Blueprint และตั้ง `generateValue: true` ให้ JWT_SECRET อัตโนมัติ

ถ้าใช้ Persistent Disk ให้ mount ที่ `/var/data` และตั้ง:

- `DATA_DIR=/var/data/data`
- `UPLOAD_DIR=/var/data/uploads`

ถ้าใช้ Free Web Service ให้เอา Persistent Disk ออก เพราะ filesystem ของบริการจะไม่ถาวร

## ตรวจระบบ

`GET /api/health`

ควรได้ JSON ที่มี `ok: true`

## หมายเหตุเรื่องข้อมูล

เวอร์ชันนี้ยังใช้ LowDB/JSON เพื่อให้ติดตั้งง่าย หากต้องการรองรับหลาย instance และข้อมูลระดับ Production ควรเปลี่ยนเป็น PostgreSQL และ object storage เช่น S3/R2/MinIO
