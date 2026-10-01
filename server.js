require('dotenv').config();
const express=require('express');
const http=require('http');
const path=require('path');
const fs=require('fs');
const crypto=require('crypto');
const jwt=require('jsonwebtoken');
const bcrypt=require('bcryptjs');
const multer=require('multer');
const helmet=require('helmet');
const cors=require('cors');
const rateLimit=require('express-rate-limit');
const {Low}=require('lowdb');
const {JSONFile}=require('lowdb/node');
const {Server}=require('socket.io');

const PORT=Number(process.env.PORT||3000);
const MAX_UPLOAD_MB=Math.max(1,Math.min(100,Number(process.env.MAX_UPLOAD_MB||25)));
const MAX_UPLOAD_FILES=Math.max(1,Math.min(20,Number(process.env.MAX_UPLOAD_FILES||10)));
const dataDir=path.resolve(process.env.DATA_DIR||path.join(__dirname,'data'));
const uploadDir=path.resolve(process.env.UPLOAD_DIR||path.join(__dirname,'uploads'));
const publicDir=path.join(__dirname,'public');
fs.mkdirSync(dataDir,{recursive:true}); fs.mkdirSync(uploadDir,{recursive:true});

// Render-safe JWT secret handling:
// 1) Use JWT_SECRET when supplied by Render Environment Variables.
// 2) Otherwise create and persist a random secret under DATA_DIR. This allows
// an existing Render service to boot even if JWT_SECRET was not configured.
const jwtSecretFile=path.join(dataDir,'.jwt-secret');
let JWT_SECRET=String(process.env.JWT_SECRET||'').trim();
if(JWT_SECRET.length<32){
  try {
    if(fs.existsSync(jwtSecretFile)) JWT_SECRET=fs.readFileSync(jwtSecretFile,'utf8').trim();
    if(JWT_SECRET.length<32){
      JWT_SECRET=crypto.randomBytes(48).toString('base64url');
      fs.writeFileSync(jwtSecretFile,JWT_SECRET,{encoding:'utf8',mode:0o600});
      console.log('JWT_SECRET was not set; generated a persistent secret in DATA_DIR.');
    }
  } catch(e) {
    console.error('Unable to create JWT secret:',e.message);
    process.exit(1);
  }
}

const app=express(); const server=http.createServer(app);
const corsConfigured=String(process.env.CORS_ORIGINS||'').trim();
const origins=corsConfigured.split(',').map(x=>x.trim()).filter(Boolean);
const corsOrigin=(origin,cb)=>{ if(!origin || !origins.length || origins.includes(origin)) return cb(null,true); return cb(new Error('CORS blocked')); };
const io=new Server(server,{cors:{origin:corsOrigin,credentials:true}});
const db=new Low(new JSONFile(path.join(dataDir,'db.json')),{users:[],groups:[],channels:[],members:[],messages:[],reactions:[],webhooks:[],webhookLogs:[],notifications:[],audit:[]});
const now=()=>new Date().toISOString(); const id=p=>p+'_'+crypto.randomBytes(9).toString('hex');
const safeUser=u=>u?{id:u.id,username:u.username,displayName:u.displayName,avatar:u.avatar||'',createdAt:u.createdAt}:null;
const save=()=>db.write();
async function init(){await db.read(); if(!db.data)db.data={users:[],groups:[],channels:[],members:[],messages:[],reactions:[],webhooks:[],webhookLogs:[],notifications:[],audit:[]}; for(const k of ['users','groups','channels','members','messages','reactions','webhooks','webhookLogs','notifications','audit'])if(!Array.isArray(db.data[k]))db.data[k]=[]; await save()}
function isMember(g,u){return db.data.members.some(x=>x.groupId===g&&x.userId===u)}
function isOwner(g,u){return db.data.groups.some(x=>x.id===g&&x.ownerId===u)}
function canManage(g,u){return isOwner(g,u)||db.data.members.some(x=>x.groupId===g&&x.userId===u&&['owner','admin'].includes(x.role))}
function channel(idv){return db.data.channels.find(x=>x.id===idv)}
function messagePublic(m){const out={...m,author:safeUser(db.data.users.find(u=>u.id===m.authorId))||{displayName:m.webhookName||'Webhook',username:''}}; delete out.authorId; return out}
function audit(actor,action,meta={}){db.data.audit.push({id:id('aud'),actorId:actor,action,meta,createdAt:now()}); if(db.data.audit.length>5000)db.data.audit=db.data.audit.slice(-5000)}
function tokenFor(u){return jwt.sign({sub:u.id},JWT_SECRET,{expiresIn:'7d'})}
function auth(req,res,next){try{const h=req.headers.authorization||'';if(!h.startsWith('Bearer '))return res.status(401).json({error:'กรุณาเข้าสู่ระบบ'});const p=jwt.verify(h.slice(7),JWT_SECRET);const u=db.data.users.find(x=>x.id===p.sub);if(!u)return res.status(401).json({error:'บัญชีไม่พบ'});req.user=u;next()}catch{return res.status(401).json({error:'Token ไม่ถูกต้องหรือหมดอายุ'})}}
function safeName(n){return path.basename(String(n||'file')).replace(/[\x00-\x1f<>:"/\\|?*]/g,'_').slice(0,180)||'file'}
function fileType(m){return String(m||'').toLowerCase()}
const blockedExt=new Set(['.html','.htm','.js','.mjs','.cjs','.php','.asp','.aspx','.jsp','.cgi','.sh','.bat','.cmd','.ps1','.vbs','.wsf']);
const storage=multer.diskStorage({destination:uploadDir,filename:(req,file,cb)=>cb(null,Date.now()+'_'+crypto.randomBytes(12).toString('hex')+path.extname(safeName(file.originalname)).toLowerCase())});
const upload=multer({storage,limits:{fileSize:MAX_UPLOAD_MB*1024*1024,files:MAX_UPLOAD_FILES,fields:10,fieldSize:100*1024,fieldNameSize:200,fieldArraySize:100,fieldArrayIndexLimit:1000},fileFilter:(req,file,cb)=>{if(blockedExt.has(path.extname(safeName(file.originalname)).toLowerCase()))return cb(new Error('ชนิดไฟล์นี้ถูกปิดเพื่อความปลอดภัย'));cb(null,true)}});

app.set('trust proxy',1);
app.use(helmet({
  crossOriginResourcePolicy:{policy:'same-site'},
  contentSecurityPolicy:{
    directives:{
      defaultSrc:["'self'"],
      scriptSrc:["'self'","'unsafe-inline'"],
      styleSrc:["'self'","'unsafe-inline'"],
      imgSrc:["'self'",'data:','blob:'],
      connectSrc:["'self'",'ws:','wss:','https:'],
      frameSrc:["'self'"],
      objectSrc:["'none'"]
    }
  }
}));
app.use(cors({origin:corsOrigin,credentials:true}));
app.use(express.json({limit:'2mb',verify:(req,res,buf)=>{if(req.path.startsWith('/api/v1/webhooks/'))req.rawBody=Buffer.from(buf)}}));
app.use(express.urlencoded({extended:true,limit:'100kb'}));
const apiLimiter=rateLimit({windowMs:60*1000,max:180,standardHeaders:true,legacyHeaders:false});
const authLimiter=rateLimit({windowMs:15*60*1000,max:40,standardHeaders:true,legacyHeaders:false});
app.use('/api/',apiLimiter);
app.get('/api/health',(req,res)=>res.json({ok:true,service:'Chat Platform',time:now(),version:'3.0.0'}));

app.post('/api/v1/auth/register',authLimiter,async(req,res)=>{const username=String(req.body.username||'').trim().toLowerCase();const displayName=String(req.body.displayName||username).trim().slice(0,50);const password=String(req.body.password||'');if(!/^[a-z0-9_]{3,24}$/.test(username))return res.status(400).json({error:'Username 3-24 ตัว ใช้ a-z 0-9 _'});if(password.length<8)return res.status(400).json({error:'รหัสผ่านอย่างน้อย 8 ตัว'});if(db.data.users.some(u=>u.username===username))return res.status(409).json({error:'Username นี้มีแล้ว'});const u={id:id('usr'),username,displayName:displayName||username,passwordHash:await bcrypt.hash(password,12),createdAt:now()};db.data.users.push(u);audit(u.id,'auth.register');await save();res.json({token:tokenFor(u),user:safeUser(u)})});
app.post('/api/v1/auth/login',authLimiter,async(req,res)=>{const username=String(req.body.username||'').trim().toLowerCase(),password=String(req.body.password||'');const u=db.data.users.find(x=>x.username===username);if(!u||!(await bcrypt.compare(password,u.passwordHash)))return res.status(401).json({error:'Username หรือ Password ไม่ถูกต้อง'});audit(u.id,'auth.login');await save();res.json({token:tokenFor(u),user:safeUser(u)})});
app.get('/api/v1/users/me',auth,(req,res)=>res.json({user:safeUser(req.user)}));

app.get('/api/v1/groups',auth,(req,res)=>res.json({groups:db.data.groups.filter(g=>isMember(g.id,req.user.id)).map(g=>({...g,channels:db.data.channels.filter(c=>c.groupId===g.id)}))}));
app.post('/api/v1/groups',auth,async(req,res)=>{const name=String(req.body.name||'').trim().slice(0,60);if(!name)return res.status(400).json({error:'กรุณาใส่ชื่อกลุ่ม'});const g={id:id('grp'),name,ownerId:req.user.id,createdAt:now()};db.data.groups.push(g);db.data.members.push({id:id('mem'),groupId:g.id,userId:req.user.id,role:'owner',createdAt:now()});db.data.channels.push({id:id('chn'),groupId:g.id,name:'general',type:'text',createdAt:now()});audit(req.user.id,'group.create',{groupId:g.id});await save();res.json({group:g})});
app.post('/api/v1/groups/:id/members',auth,async(req,res)=>{const gid=req.params.id;if(!canManage(gid,req.user.id))return res.status(403).json({error:'ไม่มีสิทธิ์'});const username=String(req.body.username||'').trim().toLowerCase();const u=db.data.users.find(x=>x.username===username);if(!u)return res.status(404).json({error:'ไม่พบผู้ใช้'});if(isMember(gid,u.id))return res.status(409).json({error:'เป็นสมาชิกอยู่แล้ว'});db.data.members.push({id:id('mem'),groupId:gid,userId:u.id,role:'member',createdAt:now()});audit(req.user.id,'member.add',{groupId:gid,userId:u.id});await save();res.json({ok:true})});
app.get('/api/v1/groups/:id/members',auth,(req,res)=>{if(!isMember(req.params.id,req.user.id))return res.status(403).json({error:'ไม่มีสิทธิ์'});res.json({members:db.data.members.filter(m=>m.groupId===req.params.id).map(m=>({...m,user:safeUser(db.data.users.find(u=>u.id===m.userId))}))})});
app.post('/api/v1/groups/:id/channels',auth,async(req,res)=>{const gid=req.params.id;if(!canManage(gid,req.user.id))return res.status(403).json({error:'ไม่มีสิทธิ์'});const name=String(req.body.name||'').trim().toLowerCase().replace(/[^a-z0-9ก-๙_-]+/g,'-').slice(0,40);if(!name)return res.status(400).json({error:'ชื่อ channel ไม่ถูกต้อง'});if(db.data.channels.some(c=>c.groupId===gid&&c.name===name))return res.status(409).json({error:'มี channel นี้แล้ว'});const c={id:id('chn'),groupId:gid,name,type:'text',createdAt:now()};db.data.channels.push(c);audit(req.user.id,'channel.create',{channelId:c.id});await save();res.json({channel:c})});

app.get('/api/v1/channels/:id/messages',auth,(req,res)=>{const c=channel(req.params.id);if(!c||!isMember(c.groupId,req.user.id))return res.status(404).json({error:'ไม่พบ channel'});const limit=Math.min(100,Math.max(1,Number(req.query.limit||50)));const before=req.query.before?String(req.query.before):null;let list=db.data.messages.filter(m=>m.channelId===c.id&&!m.deletedAt);if(before){const idx=list.findIndex(m=>m.id===before);if(idx>=0)list=list.slice(0,idx)}const msgs=list.slice(-limit).map(messagePublic);res.json({messages:msgs,hasMore:list.length>msgs.length,nextBefore:msgs[0]?.id||null})});
function mentionNotify(content,m,c){for(const name of [...String(content||'').matchAll(/@([a-z0-9_]{3,24})/gi)].map(x=>x[1].toLowerCase())){const u=db.data.users.find(x=>x.username===name);if(u&&u.id!==m.authorId&&!db.data.notifications.some(n=>n.messageId===m.id&&n.userId===u.id))db.data.notifications.push({id:id('not'),userId:u.id,channelId:c.id,messageId:m.id,type:'mention',read:false,createdAt:now()})}}
app.post('/api/v1/channels/:id/messages',auth,async(req,res)=>{const c=channel(req.params.id);if(!c||!isMember(c.groupId,req.user.id))return res.status(403).json({error:'ไม่มีสิทธิ์'});const content=String(req.body.content||'').trim().slice(0,4000);if(!content)return res.status(400).json({error:'ข้อความว่าง'});const m={id:id('msg'),channelId:c.id,authorId:req.user.id,content,attachments:[],replyTo:req.body.replyTo||null,source:'user',createdAt:now(),editedAt:null,deletedAt:null};db.data.messages.push(m);mentionNotify(content,m,c);audit(req.user.id,'message.create',{messageId:m.id});await save();io.to(c.id).emit('message:new',messagePublic(m));res.json({message:messagePublic(m)})});

app.post('/api/v1/channels/:id/upload',auth,upload.array('files',MAX_UPLOAD_FILES),async(req,res)=>{const c=channel(req.params.id);if(!c||!isMember(c.groupId,req.user.id)){for(const f of req.files||[])fs.unlink(f.path,()=>{});return res.status(403).json({error:'ไม่มีสิทธิ์'})}try{const files=(req.files||[]).map(f=>({id:id('file'),storageName:path.basename(f.filename),name:safeName(f.originalname),mime:fileType(f.mimetype)||'application/octet-stream',size:f.size,uploadedAt:now()}));const content=String(req.body.content||'').trim().slice(0,4000);if(!files.length&&!content)return res.status(400).json({error:'กรุณาเลือกไฟล์หรือใส่ข้อความ'});const m={id:id('msg'),channelId:c.id,authorId:req.user.id,content,attachments:files,replyTo:req.body.replyTo||null,source:'user',createdAt:now(),editedAt:null,deletedAt:null};db.data.messages.push(m);mentionNotify(content,m,c);audit(req.user.id,'file.upload',{messageId:m.id,count:files.length});await save();io.to(c.id).emit('message:new',messagePublic(m));res.json({message:messagePublic(m)})}catch(e){for(const f of req.files||[])fs.unlink(f.path,()=>{});res.status(500).json({error:'อัปโหลดไม่สำเร็จ'})}});

app.get('/api/v1/files/:fileId',auth,(req,res)=>{let found=null;for(const m of db.data.messages){const a=(m.attachments||[]).find(x=>x.id===req.params.fileId);if(a){found={m,a};break}}if(!found)return res.status(404).end();const c=channel(found.m.channelId);if(!c||!isMember(c.groupId,req.user.id))return res.status(403).end();const disk=path.join(uploadDir,path.basename(found.a.storageName));if(!fs.existsSync(disk))return res.status(404).end();res.setHeader('X-Content-Type-Options','nosniff');const inline=req.query.inline==='1'&&(/^(image\/(png|jpeg|gif|webp)|application\/pdf)$/i.test(found.a.mime));res.setHeader('Content-Type',found.a.mime);res.setHeader('Content-Disposition',(inline?'inline':'attachment')+`; filename="${found.a.name.replace(/"/g,'')}"`);res.sendFile(disk)})

app.post('/api/v1/messages/:id/reactions',auth,async(req,res)=>{const m=db.data.messages.find(x=>x.id===req.params.id);if(!m)return res.status(404).json({error:'ไม่พบข้อความ'});const c=channel(m.channelId);if(!c||!isMember(c.groupId,req.user.id))return res.status(403).json({error:'ไม่มีสิทธิ์'});const emoji=String(req.body.emoji||'👍').slice(0,8);const old=db.data.reactions.find(r=>r.messageId===m.id&&r.userId===req.user.id&&r.emoji===emoji);if(old)db.data.reactions=db.data.reactions.filter(r=>r.id!==old.id);else db.data.reactions.push({id:id('rx'),messageId:m.id,userId:req.user.id,emoji,createdAt:now()});await save();io.to(m.channelId).emit('reaction:update',{messageId:m.id,reactions:db.data.reactions.filter(r=>r.messageId===m.id)});res.json({ok:true})});
app.patch('/api/v1/messages/:id',auth,async(req,res)=>{const m=db.data.messages.find(x=>x.id===req.params.id);if(!m)return res.status(404).json({error:'ไม่พบข้อความ'});const c=channel(m.channelId);if(!c||!isMember(c.groupId,req.user.id)||m.authorId!==req.user.id)return res.status(403).json({error:'ไม่มีสิทธิ์'});const content=String(req.body.content||'').trim().slice(0,4000);if(!content)return res.status(400).json({error:'ข้อความว่าง'});m.content=content;m.editedAt=now();audit(req.user.id,'message.edit',{messageId:m.id});await save();io.to(m.channelId).emit('message:update',messagePublic(m));res.json({message:messagePublic(m)})});
app.delete('/api/v1/messages/:id',auth,async(req,res)=>{const m=db.data.messages.find(x=>x.id===req.params.id);if(!m)return res.status(404).json({error:'ไม่พบข้อความ'});const c=channel(m.channelId);if(!c||!isMember(c.groupId,req.user.id))return res.status(403).json({error:'ไม่มีสิทธิ์'});if(m.authorId!==req.user.id&&!canManage(c.groupId,req.user.id))return res.status(403).json({error:'ไม่มีสิทธิ์'});m.deletedAt=now();m.deletedBy=req.user.id;m.content='';m.attachments=[];audit(req.user.id,'message.delete',{messageId:m.id});await save();io.to(m.channelId).emit('message:delete',{id:m.id});res.json({ok:true})});

app.get('/api/v1/notifications',auth,(req,res)=>{const n=db.data.notifications.filter(x=>x.userId===req.user.id).sort((a,b)=>b.createdAt.localeCompare(a.createdAt)).slice(0,100);res.json({notifications:n,unread:n.filter(x=>!x.read).length})});
app.post('/api/v1/notifications/read',auth,async(req,res)=>{db.data.notifications.filter(x=>x.userId===req.user.id).forEach(x=>x.read=true);await save();res.json({ok:true})});

app.post('/api/v1/channels/:id/webhooks',auth,async(req,res)=>{const c=channel(req.params.id);if(!c||!canManage(c.groupId,req.user.id))return res.status(403).json({error:'ไม่มีสิทธิ์'});const name=String(req.body.name||'Webhook').trim().slice(0,60);const secret=crypto.randomBytes(32).toString('hex');const w={id:id('wh'),channelId:c.id,name,secretHash:await bcrypt.hash(secret,12),secret,secretPreview:secret.slice(0,8)+'...',enabled:true,createdBy:req.user.id,createdAt:now()};db.data.webhooks.push(w);audit(req.user.id,'webhook.create',{webhookId:w.id});await save();res.json({webhook:{id:w.id,name:w.name,channelId:w.channelId,enabled:true,secretPreview:w.secretPreview,createdAt:w.createdAt},secret})});
app.get('/api/v1/channels/:id/webhooks',auth,(req,res)=>{const c=channel(req.params.id);if(!c||!canManage(c.groupId,req.user.id))return res.status(403).json({error:'ไม่มีสิทธิ์'});res.json({webhooks:db.data.webhooks.filter(w=>w.channelId===c.id).map(w=>({id:w.id,name:w.name,enabled:w.enabled,secretPreview:w.secretPreview,createdAt:w.createdAt}))})});
app.delete('/api/v1/webhooks/:id',auth,async(req,res)=>{const w=db.data.webhooks.find(x=>x.id===req.params.id);if(!w)return res.status(404).json({error:'ไม่พบ webhook'});const c=channel(w.channelId);if(!c||!canManage(c.groupId,req.user.id))return res.status(403).json({error:'ไม่มีสิทธิ์'});db.data.webhooks=db.data.webhooks.filter(x=>x.id!==w.id);audit(req.user.id,'webhook.delete',{webhookId:w.id});await save();res.json({ok:true})});
function verifySig(secret,ts,raw,sig){if(!/^\d+$/.test(ts)||Math.abs(Date.now()-Number(ts))>300000||!/^sha256=[a-f0-9]{64}$/i.test(sig))return false;const expected=crypto.createHmac('sha256',secret).update(ts+'.').update(raw).digest('hex');const a=Buffer.from('sha256='+expected);const b=Buffer.from(sig);return a.length===b.length&&crypto.timingSafeEqual(a,b)}
app.post('/api/v1/webhooks/:id',async(req,res)=>{const w=db.data.webhooks.find(x=>x.id===req.params.id);if(!w||!w.enabled)return res.status(404).json({error:'Webhook ไม่พร้อมใช้งาน'});const ts=String(req.headers['x-webhook-timestamp']||'');const sig=String(req.headers['x-webhook-signature']||'');const raw=req.rawBody||Buffer.from(JSON.stringify(req.body||{}));const direct=String(req.headers['x-webhook-secret']||'');const ok=direct?await bcrypt.compare(direct,w.secretHash):verifySig(w.secret,ts,raw,sig);db.data.webhookLogs.push({id:id('whlog'),webhookId:w.id,ok,ip:req.ip,createdAt:now()});if(!ok){await save();return res.status(401).json({error:'Webhook authentication failed'})}const c=channel(w.channelId);const body=req.body||{};const m={id:id('msg'),channelId:c.id,authorId:w.createdBy,content:String(body.content||'').slice(0,4000),attachments:Array.isArray(body.attachments)?body.attachments.slice(0,5):[],replyTo:null,source:'webhook',webhookId:w.id,webhookName:String(body.username||w.name).slice(0,60),avatarUrl:String(body.avatar_url||'').slice(0,500),embeds:Array.isArray(body.embeds)?body.embeds.slice(0,5):[],createdAt:now(),editedAt:null,deletedAt:null};db.data.messages.push(m);await save();io.to(c.id).emit('message:new',messagePublic(m));res.json({ok:true,message_id:m.id})});
app.get('/api/v1/webhooks/:id/logs',auth,(req,res)=>{const w=db.data.webhooks.find(x=>x.id===req.params.id);if(!w)return res.status(404).json({error:'ไม่พบ'});const c=channel(w.channelId);if(!c||!canManage(c.groupId,req.user.id))return res.status(403).json({error:'ไม่มีสิทธิ์'});res.json({logs:db.data.webhookLogs.filter(x=>x.webhookId===w.id).slice(-100).reverse()})});

io.use((socket,next)=>{try{const p=jwt.verify(socket.handshake.auth?.token||'',JWT_SECRET);const u=db.data.users.find(x=>x.id===p.sub);if(!u)throw Error();socket.user=u;next()}catch{next(new Error('unauthorized'))}});
io.on('connection',socket=>{socket.on('join_channel',cid=>{const c=channel(cid);if(c&&isMember(c.groupId,socket.user.id))socket.join(cid)});socket.on('typing',cid=>{const c=channel(cid);if(c&&isMember(c.groupId,socket.user.id))socket.to(cid).emit('typing',{username:socket.user.username})})});

app.use('/uploads', (req,res)=>res.status(404).end());
app.use(express.static(publicDir));
app.use((err,req,res,next)=>{if(err instanceof multer.MulterError){if(err.code==='LIMIT_FILE_SIZE')return res.status(413).json({error:`ไฟล์ใหญ่เกิน ${MAX_UPLOAD_MB} MB ต่อไฟล์`});if(err.code==='LIMIT_FILE_COUNT')return res.status(400).json({error:`แนบได้ไม่เกิน ${MAX_UPLOAD_FILES} ไฟล์ต่อข้อความ`});return res.status(400).json({error:'ไฟล์ไม่ถูกต้องหรืออัปโหลดไม่สำเร็จ'})}if(err)console.error(err);res.status(500).json({error:'Server error'})});
app.use((req,res,next)=>{if(req.path.startsWith('/api/'))return res.status(404).json({error:'Not found'});if(req.method==='GET')return res.sendFile(path.join(publicDir,'index.html'));next()});

init().then(()=>server.listen(PORT,'0.0.0.0',()=>console.log(`Chat Platform running: http://localhost:${PORT}`))).catch(e=>{console.error(e);process.exit(1)});
process.on('SIGINT',async()=>{await save();server.close(()=>process.exit(0))}); process.on('SIGTERM',async()=>{await save();server.close(()=>process.exit(0))});
