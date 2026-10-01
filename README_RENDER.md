# Chat Platform Real — Render Deployment

ระบบนี้เตรียมสำหรับ Render Web Service แล้ว

## วิธี Deploy แบบ Blueprint

1. สร้าง GitHub repository ใหม่
2. แตก ZIP นี้ แล้ว push ไฟล์ทั้งหมดขึ้น GitHub
3. เข้า Render Dashboard → New → Blueprint
4. เลือก repository ที่มี `render.yaml`
5. Render จะสร้าง Web Service ชื่อ `chat-platform-real` พร้อม Persistent Disk 10 GB
6. กด Apply แล้วรอ Build/Deploy
7. เปิด URL ที่ Render สร้างให้

## ค่า Render ที่ตั้งไว้

- Runtime: Node
- Node: 22.14.0
- Build: `npm install`
- Start: `npm start`
- Health check: `/api/health`
- Persistent disk: `/var/data`
- DB: `/var/data/data/db.json`
- Uploads: `/var/data/uploads`
- JWT_SECRET: Render สร้างค่าให้โดยอัตโนมัติ

## สำคัญ

ระบบนี้ใช้ LowDB + Persistent Disk เพื่อให้ Deploy ได้ง่ายและคงข้อมูล/ไฟล์แนบไว้ใน instance เดียว เหมาะกับการเริ่มใช้งานจริงแบบ single-instance

หากต้องการขยายหลาย instance/scale-out ภายหลัง ควรย้ายข้อมูลไป Render Postgres และไฟล์ไป S3/R2/MinIO เพราะ persistent disk ใช้ร่วมกันข้าม instance ไม่ได้

## ตรวจระบบ

เปิด:
`https://YOUR-SERVICE.onrender.com/api/health`

ควรได้ JSON ประมาณ:
`{"ok":true,"service":"Chat Platform",...}`

## Local Windows

ยังใช้ `run.bat` ได้เหมือนเดิม
