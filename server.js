import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'edutruth_secret_2024_secure_key';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/edutruth';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// MongoDB Connection
mongoose.connect(MONGODB_URI).then(()=>console.log('MongoDB connected')).catch(e=>console.error('MongoDB error',e.message));

// Schemas
const userSchema = new mongoose.Schema({
  username:{type:String,required:true,unique:true},
  password_hash:{type:String,required:true},
  name:{type:String,required:true},
  email:{type:String,required:true,unique:true},
  role:{type:String,enum:['student','mentor','admin'],required:true},
  status:{type:String,enum:['pending','approved','rejected','deactivated'],default:'pending'},
  academic_details:String,
  college_name:String,
  college_location:String,
  course:String,
  department:String,
  branch:String,
  bio:String,
},{timestamps:true});
const collegeSchema = new mongoose.Schema({
  name:{type:String,required:true}, location:{type:String,required:true}, state:String,
  courses:[String], facilities:[String], infrastructure:String, placement_info:String,
  fees:String, image:String, established:String, type:String, description:String, contact_email:String, contact_phone:String, address:String, status:{type:String,enum:['approved','pending_verification','rejected'],default:'approved'}
},{timestamps:true});
const collegeSubmissionSchema = new mongoose.Schema({
  name:String, location:String, state:String, courses:[String], facilities:[String], infrastructure:String, placement_info:String, fees:String, image:String, established:String, type:String, description:String, status:{type:String,default:'pending_verification'}, submitted_by:{type:mongoose.Schema.Types.ObjectId,ref:'User'}
},{timestamps:true});
const reviewSchema = new mongoose.Schema({
  college_id:{type:mongoose.Schema.Types.ObjectId,ref:'College',required:true},
  user_id:{type:mongoose.Schema.Types.ObjectId,ref:'User',required:true},
  rating:{type:Number,required:true,min:1,max:5}, comment:String, reported:{type:Boolean,default:false}
},{timestamps:true});
reviewSchema.index({college_id:1,user_id:1},{unique:true});
const savedSchema = new mongoose.Schema({ user_id:{type:mongoose.Schema.Types.ObjectId,ref:'User'}, college_id:{type:mongoose.Schema.Types.ObjectId,ref:'College'}},{timestamps:true});
const mentorRequestSchema = new mongoose.Schema({
  student_id:{type:mongoose.Schema.Types.ObjectId,ref:'User'}, mentor_id:{type:mongoose.Schema.Types.ObjectId,ref:'User'},
  status:{type:String,enum:['pending','accepted','rejected'],default:'pending'}, message:String
},{timestamps:true});
const messageSchema = new mongoose.Schema({
  sender_id:{type:mongoose.Schema.Types.ObjectId,ref:'User'}, receiver_id:{type:mongoose.Schema.Types.ObjectId,ref:'User'},
  request_id:{type:mongoose.Schema.Types.ObjectId,ref:'MentorRequest'}, content:{type:String,required:true}
},{timestamps:true});
const notificationSchema = new mongoose.Schema({
  user_id:{type:mongoose.Schema.Types.ObjectId,ref:'User'}, title:String, message:String, read:{type:Boolean,default:false}
},{timestamps:true});

const User = mongoose.model('User', userSchema);
const College = mongoose.model('College', collegeSchema);
const CollegeSubmission = mongoose.model('CollegeSubmission', collegeSubmissionSchema);
const Review = mongoose.model('Review', reviewSchema);
const SavedCollege = mongoose.model('SavedCollege', savedSchema);
const MentorRequest = mongoose.model('MentorRequest', mentorRequestSchema);
const Message = mongoose.model('Message', messageSchema);
const Notification = mongoose.model('Notification', notificationSchema);

// Init Admin
async function initAdmin(){
  const exists = await User.findOne({username:'Naren'});
  if(!exists){
    const hash = await bcrypt.hash('7382506666',10);
    await User.create({username:'Naren', password_hash:hash, name:'Naren Admin', email:'admin@edutruth.edu', role:'admin', status:'approved'});
    console.log('Admin account created: Naren');
  }
}
mongoose.connection.once('open', initAdmin);

// Middleware
function authenticate(req,res,next){
  const token = req.headers.authorization?.replace('Bearer ','');
  if(!token) return res.status(401).json({error:'Unauthorized'});
  try{ req.user = jwt.verify(token, JWT_SECRET); next(); }catch{ res.status(401).json({error:'Invalid token'}) }
}
function authorize(...roles){ return (req,res,next)=>{ if(!roles.includes(req.user.role)) return res.status(403).json({error:'Forbidden'}); next(); }}

// Auth APIs
app.post('/api/auth', async (req,res)=>{
  const {action, username, password, name, email, role, academic_details, college_name, college_location, course, department, branch, bio, rememberMe} = req.body;
  try{
    if(action==='register'){
      if(role==='admin') return res.status(403).json({error:'Admin registration not allowed'});
      if(!username||!password||!name||!email||!role) return res.status(400).json({error:'All fields required'});
      if(role==='mentor' && !academic_details) return res.status(400).json({error:'Academic details required for mentors'});
      const hash = await bcrypt.hash(password,10);
      const user = await User.create({username, password_hash:hash, name, email, role, status:'pending', academic_details, college_name, college_location, course, department, branch, bio});
      if(role==='mentor' && college_name){
        const existing = await College.findOne({name: new RegExp(`^${college_name}$`,'i')});
        if(!existing){
          await CollegeSubmission.create({name: college_name, location: college_location||'Not specified', state: college_location||'', courses: course?[course]:[], description:`Submitted by mentor ${name} (${username}) - Dept:${department||''} Branch:${branch||''} Course:${course||''}`, status:'pending_verification', submitted_by: user._id});
        }
      }
      return res.status(201).json({message:'Your registration is submitted successfully. Please wait for Admin approval.', user:{id:user._id, username:user.username, status:user.status}});
    }
    if(action==='login'){
      const user = await User.findOne({username});
      if(!user) return res.status(401).json({error:'Invalid credentials'});
      const valid = await bcrypt.compare(password, user.password_hash);
      if(!valid) return res.status(401).json({error:'Invalid credentials'});
      if(user.status==='pending') return res.status(403).json({error:'Your account is Pending Approval. Please wait for Admin approval.'});
      if(user.status==='rejected') return res.status(403).json({error:'Your account has been Rejected by Admin. Please contact support.'});
      if(user.status!=='approved') return res.status(403).json({error:'Your account is not Approved. Login allowed only after Admin approval.'});
      const expiresIn = rememberMe===false ? '1d' : '7d';
      const token = jwt.sign({id:user._id, username:user.username, role:user.role}, JWT_SECRET, {expiresIn});
      return res.json({token, user:{id:user._id, username:user.username, name:user.name, email:user.email, role:user.role, status:user.status, academic_details:user.academic_details, college_name:user.college_name, college_location:user.college_location, course:user.course, department:user.department, branch:user.branch, bio:user.bio}});
    }
    res.status(400).json({error:'Invalid action'});
  }catch(e){ if(e.code===11000) return res.status(409).json({error:'Username or email already exists'}); res.status(500).json({error:e.message}) }
});

app.get('/api/users', authenticate, async (req,res)=>{
  const {role,status,id}=req.query;
  const filter={}; if(role) filter.role=role; if(status) filter.status=status; if(id) filter._id=id;
  if(req.user.role!=='admin'){ filter.role='mentor'; filter.status='approved'; }
  const users = await User.find(filter).select('-password_hash').sort({createdAt:-1});
  res.json(users);
});
app.put('/api/users', authenticate, async (req,res)=>{
  const {id,status,name,email,username,academic_details,college_name,college_location,course,department,branch,bio,role,new_password}=req.body;
  const target=await User.findById(id); if(target && (target.role==='admin' || target.username==='Naren')) return res.status(403).json({error:'Predefined Admin account is protected from modification via user management'});
  if(new_password!==undefined){
    if(req.user.role!=='admin') return res.status(403).json({error:'Only admin can reset passwords'});
    if(!new_password || new_password.length<6) return res.status(400).json({error:'Password must be at least 6 characters'});
    const hashed=await bcrypt.hash(new_password,10);
    await User.findByIdAndUpdate(id,{password_hash:hashed});
    await Notification.create({user_id:id, title:'Password Reset', message:'Your password was reset by Admin.'});
    return res.json({message:'Password reset securely — stored as bcrypt hash'});
  }
  if(role==='admin') return res.status(403).json({error:'Admin role not allowed'});
  if(req.user.role!=='admin' && id!==req.user.id) return res.status(403).json({error:'Forbidden'});
  const allowedStatuses=['pending','approved','rejected','deactivated']; if(status && !allowedStatuses.includes(status)) return res.status(400).json({error:'Invalid status'});
  const updates={}; if(status && req.user.role==='admin') updates.status=status; if(name) updates.name=name; if(email) updates.email=email; if(username) updates.username=username; if(academic_details!==undefined) updates.academic_details=academic_details; if(college_name!==undefined) updates.college_name=college_name; if(college_location!==undefined) updates.college_location=college_location; if(course!==undefined) updates.course=course; if(department!==undefined) updates.department=department; if(branch!==undefined) updates.branch=branch; if(bio!==undefined) updates.bio=bio;
  const user = await User.findByIdAndUpdate(id, updates, {new:true}).select('-password_hash');
  if(status) await Notification.create({user_id:id, title: status==='approved'?'Account Approved':'Account Rejected', message:`Your account status is now ${status}`});
  res.json(user);
});
app.post('/api/users', authenticate, authorize('admin'), async (req,res)=>{
  const {name,username,email,password,role,college_name,status}=req.body;
  if(!name||!username||!email||!password||!role) return res.status(400).json({error:'All fields required'});
  if(role==='admin') return res.status(403).json({error:'Admin creation not allowed via user management'});
  const hash=await bcrypt.hash(password,10);
  const user=await User.create({username,password_hash:hash,name,email,role,status:status||'approved',college_name});
  res.status(201).json({message:'Account created and persisted in MongoDB', user:{id:user._id, username:user.username}});
});
app.delete('/api/users', authenticate, authorize('admin'), async (req,res)=>{ 
  const target=await User.findById(req.body.id); if(target && (target.role==='admin' || target.username==='Naren')) return res.status(403).json({error:'Predefined Admin account cannot be deleted'});
  await SavedCollege.deleteMany({user_id:req.body.id}); await Review.deleteMany({user_id:req.body.id}); await MentorRequest.deleteMany({student_id:req.body.id}); await MentorRequest.deleteMany({mentor_id:req.body.id}); await Message.deleteMany({sender_id:req.body.id}); await Message.deleteMany({receiver_id:req.body.id}); await Notification.deleteMany({user_id:req.body.id});
  await User.findByIdAndDelete(req.body.id); res.json({ok:true}) });

app.get('/api/colleges', async (req,res)=>{
  const {search,location,course,id}=req.query;
  const filter={}; if(id) filter._id=id;
  let colleges = await College.find({...filter, status:'approved'}).sort({createdAt:-1});
  // include legacy colleges without status field
  const legacy = await College.find({status:{$exists:false}}).sort({createdAt:-1});
  colleges = [...colleges, ...legacy];
  if(search) colleges=colleges.filter(c=> c.name.toLowerCase().includes(search.toLowerCase())||c.location.toLowerCase().includes(search.toLowerCase()));
  if(location) colleges=colleges.filter(c=> c.location.toLowerCase().includes(location.toLowerCase()));
  if(course) colleges=colleges.filter(c=> c.courses?.some(co=>co.toLowerCase().includes(course.toLowerCase())));
  res.json(colleges);
});
app.post('/api/colleges', authenticate, authorize('admin'), async (req,res)=>{ const c=await College.create(req.body); res.status(201).json(c)});
app.put('/api/colleges', authenticate, authorize('admin'), async (req,res)=>{ const {id,...u}=req.body; const c=await College.findByIdAndUpdate(id,u,{new:true}); res.json(c)});
app.delete('/api/colleges', authenticate, authorize('admin'), async (req,res)=>{ await College.findByIdAndDelete(req.body.id); res.json({ok:true})});\napp.get('/api/college-submissions', authenticate, authorize('admin'), async (req,res)=>{ res.json(await CollegeSubmission.find().sort({createdAt:-1}))});\napp.put('/api/college-submissions', authenticate, authorize('admin'), async (req,res)=>{\n  const {id,status,...updates}=req.body;\n  const sub=await CollegeSubmission.findById(id);\n  if(!sub) return res.status(404).json({error:'Not found'});\n  if(status==='approved'){\n    const college=await College.create({name: updates.name||sub.name, location: updates.location||sub.location, state: updates.state||sub.state, courses: updates.courses||sub.courses||[], facilities: updates.facilities||sub.facilities||[], infrastructure: updates.infrastructure||sub.infrastructure||'', placement_info: updates.placement_info||sub.placement_info||'', fees: updates.fees||sub.fees||'', image: updates.image||sub.image||'', established: updates.established||sub.established||'', type: updates.type||sub.type||'', description: updates.description||sub.description||'', status:'approved'});\n    sub.status='approved'; await sub.save();\n    return res.json(college);\n  } else { sub.status=status; Object.assign(sub, updates); await sub.save(); return res.json(sub); }\n});

app.get('/api/reviews', async (req,res)=>{
  const filter={}; if(req.query.college_id) filter.college_id=req.query.college_id;
  const reviews = await Review.find(filter).populate('user_id','name username').sort({createdAt:-1});
  res.json(reviews.map(r=>({...r.toObject(), user:r.user_id})));
});
app.post('/api/reviews', authenticate, async (req,res)=>{
  if(req.user.role!=='student') return res.status(403).json({error:'Only students can review'});
  const {college_id, rating, comment}=req.body;
  try{ const r=await Review.create({college_id, user_id:req.user.id, rating, comment}); res.status(201).json(r)}catch(e){ if(e.code===11000) return res.status(409).json({error:'Already reviewed'}); throw e }
});
app.delete('/api/reviews', authenticate, async (req,res)=>{
  const review = await Review.findById(req.body.id);
  if(req.user.role!=='admin' && review.user_id.toString()!==req.user.id) return res.status(403).json({error:'Forbidden'});
  await Review.findByIdAndDelete(req.body.id); res.json({ok:true})
});

app.get('/api/saved', authenticate, async (req,res)=>{
  const saved = await SavedCollege.find({user_id:req.user.id}).populate('college_id');
  res.json(saved.map(s=>({...s.toObject(), college:s.college_id})));
});
app.post('/api/saved', authenticate, async (req,res)=>{
  const exists = await SavedCollege.findOne({user_id:req.user.id, college_id:req.body.college_id});
  if(exists) return res.status(409).json({error:'Already saved'});
  const s=await SavedCollege.create({user_id:req.user.id, college_id:req.body.college_id}); res.status(201).json(s)
});
app.delete('/api/saved', authenticate, async (req,res)=>{
  await SavedCollege.deleteOne({user_id:req.user.id, college_id:req.body.college_id}); res.json({ok:true})
});

app.get('/api/mentor-requests', authenticate, async (req,res)=>{
  const filter={}; if(req.user.role==='student') filter.student_id=req.user.id; else if(req.user.role==='mentor') filter.mentor_id=req.user.id;
  const reqs = await MentorRequest.find(filter).populate('student_id','name username college_name').populate('mentor_id','name username college_name').sort({createdAt:-1});
  res.json(reqs.map(r=>({...r.toObject(), student:r.student_id, mentor:r.mentor_id})));
});
app.post('/api/mentor-requests', authenticate, async (req,res)=>{
  if(req.user.role!=='student') return res.status(403).json({error:'Only students can send requests'});
  const exists = await MentorRequest.findOne({student_id:req.user.id, mentor_id:req.body.mentor_id, status:{$in:['pending','accepted']}});
  if(exists) return res.status(409).json({error:'Request already exists'});
  const r=await MentorRequest.create({student_id:req.user.id, mentor_id:req.body.mentor_id, message:req.body.message});
  await Notification.create({user_id:req.body.mentor_id, title:'New Mentorship Request', message:'You have a new request'});
  res.status(201).json(r)
});
app.put('/api/mentor-requests', authenticate, async (req,res)=>{
  const r=await MentorRequest.findById(req.body.id);
  if(req.user.role!=='mentor' || r.mentor_id.toString()!==req.user.id) return res.status(403).json({error:'Forbidden'});
  r.status=req.body.status; await r.save();
  await Notification.create({user_id:r.student_id, title: r.status==='accepted'?'Request Accepted':'Request Rejected', message:`Your request was ${r.status}`});
  res.json(r)
});

app.get('/api/messages', authenticate, async (req,res)=>{
  const {request_id, other_user_id}=req.query;
  let filter={};
  if(request_id) filter.request_id=request_id;
  else if(other_user_id) filter={$or:[{sender_id:req.user.id, receiver_id:other_user_id},{sender_id:other_user_id, receiver_id:req.user.id}]};
  const msgs = await Message.find(filter).sort({createdAt:1}); res.json(msgs)
});
app.post('/api/messages', authenticate, async (req,res)=>{
  const {receiver_id, request_id, content}=req.body;
  if(request_id){ const mr=await MentorRequest.findById(request_id); if(!mr||mr.status!=='accepted') return res.status(403).json({error:'Chat only after acceptance'}) }
  const m=await Message.create({sender_id:req.user.id, receiver_id, request_id, content});
  await Notification.create({user_id:receiver_id, title:'New Message', message:'You have a new message'});
  res.status(201).json(m)
});

app.get('/api/notifications', authenticate, async (req,res)=>{ res.json(await Notification.find({user_id:req.user.id}).sort({createdAt:-1}))});
app.put('/api/notifications', authenticate, async (req,res)=>{
  if(req.body.id) await Notification.findByIdAndUpdate(req.body.id,{read:req.body.read});
  else await Notification.updateMany({user_id:req.user.id},{read:true});
  res.json({ok:true})
});

app.get('/api/stats', authenticate, authorize('admin'), async (req,res)=>{
  const totalStudents=await User.countDocuments({role:'student'});
  const totalMentors=await User.countDocuments({role:'mentor'});
  const pendingStudents=await User.countDocuments({role:'student',status:'pending'});
  const pendingMentors=await User.countDocuments({role:'mentor',status:'pending'});
  const approvedStudents=await User.countDocuments({role:'student',status:'approved'});
  const approvedMentors=await User.countDocuments({role:'mentor',status:'approved'});
  const rejectedStudents=await User.countDocuments({role:'student',status:'rejected'});
  const rejectedMentors=await User.countDocuments({role:'mentor',status:'rejected'});
  const deactivatedStudents=await User.countDocuments({role:'student',status:'deactivated'});
  const deactivatedMentors=await User.countDocuments({role:'mentor',status:'deactivated'});
  const totalColleges=await College.countDocuments();
  const combinedTotal=totalStudents+totalMentors;
  const pending=pendingStudents+pendingMentors;
  const approved=approvedStudents+approvedMentors;
  const rejected=rejectedStudents+rejectedMentors;
  const deactivated=deactivatedStudents+deactivatedMentors;
  res.json({totalStudents,totalMentors,combinedTotal,pendingStudents,pendingMentors,approvedStudents,approvedMentors,rejectedStudents,rejectedMentors,deactivatedStudents,deactivatedMentors,pending,approved,rejected,deactivated,active:approved,totalColleges,pendingApprovals:pending});
});

app.get('*', (req,res)=> res.sendFile(path.join(__dirname,'index.html')));

app.listen(PORT, ()=>console.log(`EduTruth server running on port ${PORT}`));
