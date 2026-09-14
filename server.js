const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(express.json({ limit: '5mb' }));
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

/* =========================================================
   MODELS
   ========================================================= */
const User = mongoose.model('User', new mongoose.Schema({
  username: { type: String, unique: true, required: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  name:     { type: String, required: true },
  role:     { type: String, enum: ['teacher', 'student'], default: 'student' }
}, { timestamps: true }));

const Exam = mongoose.model('Exam', new mongoose.Schema({
  title:    { type: String, required: true },
  subject:  { type: String, required: true },
  duration: { type: Number, required: true },
  questions: [{
    text: String,
    options: [String],
    correct: Number
  }],
  createdBy:  { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  assignedTo: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt:  { type: Date, default: Date.now }
}));

const Result = mongoose.model('Result', new mongoose.Schema({
  examId: { type: mongoose.Schema.Types.ObjectId, ref: 'Exam', required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  score: Number,
  correct: Number,
  total: Number,
  answers: Object,
  submittedAt: { type: Date, default: Date.now }
}));

/* =========================================================
   AUTH MIDDLEWARE
   ========================================================= */
const JWT_SECRET = process.env.JWT_SECRET || 'khaothi-secret-please-change';

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Chưa đăng nhập' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: 'Phiên hết hạn, vui lòng đăng nhập lại' });
  }
}

function onlyTeacher(req, res, next) {
  if (req.user.role !== 'teacher')
    return res.status(403).json({ error: 'Chỉ giảng viên mới được thực hiện' });
  next();
}

/* =========================================================
   SEED — Tạo giảng viên Hbinh nếu chưa có
   ========================================================= */
async function seed() {
  const teacher = await User.findOne({ username: 'hbinh' });
  if (!teacher) {
    await User.create({
      username: 'hbinh',
      password: await bcrypt.hash('Hb@22052007', 10),
      name: 'Hbinh',
      role: 'teacher'
    });
    console.log('✅ Đã tạo giảng viên: Hbinh');
  } else {
    console.log('ℹ️  Giảng viên Hbinh đã tồn tại');
  }
}

/* =========================================================
   AUTH ROUTES
   ========================================================= */
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, name } = req.body;
    if (!username || !password || !name)
      return res.status(400).json({ error: 'Thiếu thông tin' });
    if (username.length < 3)
      return res.status(400).json({ error: 'Tên đăng nhập tối thiểu 3 ký tự' });
    if (password.length < 6)
      return res.status(400).json({ error: 'Mật khẩu tối thiểu 6 ký tự' });

    const exist = await User.findOne({ username: username.toLowerCase() });
    if (exist) return res.status(400).json({ error: 'Tên đăng nhập đã tồn tại' });

    // ⚠️ Đăng ký chỉ tạo được HỌC SINH
    const user = await User.create({
      username: username.toLowerCase(),
      password: await bcrypt.hash(password, 10),
      name,
      role: 'student'
    });

    const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
    res.json({
      token,
      user: { id: user._id, username: user.username, name: user.name, role: user.role }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: 'Nhập tên đăng nhập và mật khẩu' });

    const user = await User.findOne({ username: username.toLowerCase() });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(400).json({ error: 'Sai tên đăng nhập hoặc mật khẩu' });

    const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
    res.json({
      token,
      user: { id: user._id, username: user.username, name: user.name, role: user.role }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/me', auth, async (req, res) => {
  const user = await User.findById(req.user.id).select('-password');
  res.json(user);
});

/* =========================================================
   EXAM ROUTES
   ========================================================= */
app.get('/api/exams', auth, async (req, res) => {
  try {
    const query = req.user.role === 'teacher'
      ? { createdBy: req.user.id }
      : { assignedTo: req.user.id };
    const exams = await Exam.find(query).sort({ createdAt: -1 });
    res.json(exams);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/exams', auth, onlyTeacher, async (req, res) => {
  try {
    const { title, subject, duration, questions } = req.body;
    if (!title || !subject || !duration || !Array.isArray(questions))
      return res.status(400).json({ error: 'Dữ liệu đề không hợp lệ' });

    const exam = await Exam.create({
      title, subject, duration, questions,
      createdBy: req.user.id,
      assignedTo: []
    });
    res.json(exam);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/exams/:id', auth, onlyTeacher, async (req, res) => {
  try {
    const exam = await Exam.findOneAndUpdate(
      { _id: req.params.id, createdBy: req.user.id },
      req.body,
      { new: true }
    );
    if (!exam) return res.status(404).json({ error: 'Không tìm thấy đề' });
    res.json(exam);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/exams/:id', auth, onlyTeacher, async (req, res) => {
  try {
    const exam = await Exam.findOneAndDelete({ _id: req.params.id, createdBy: req.user.id });
    if (exam) await Result.deleteMany({ examId: exam._id });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* =========================================================
   STUDENT ROUTES
   ========================================================= */
app.get('/api/students', auth, onlyTeacher, async (req, res) => {
  try {
    const students = await User.find({ role: 'student' }).select('-password').sort({ name: 1 });
    res.json(students);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/students', auth, onlyTeacher, async (req, res) => {
  try {
    const { username, password, name } = req.body;
    if (!username || !password || !name)
      return res.status(400).json({ error: 'Thiếu thông tin' });
    if (await User.findOne({ username: username.toLowerCase() }))
      return res.status(400).json({ error: 'Tên đăng nhập đã tồn tại' });

    const user = await User.create({
      username: username.toLowerCase(),
      password: await bcrypt.hash(password, 10),
      name,
      role: 'student'
    });
    res.json({ id: user._id, username: user.username, name: user.name, role: user.role });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* =========================================================
   RESULT ROUTES
   ========================================================= */
app.get('/api/results', auth, async (req, res) => {
  try {
    if (req.user.role === 'teacher') {
      const exams = await Exam.find({ createdBy: req.user.id }).select('_id title subject');
      const examIds = exams.map(e => e._id);
      const results = await Result.find({ examId: { $in: examIds } }).sort({ submittedAt: -1 });

      const userIds = [...new Set(results.map(r => r.userId.toString()))];
      const users = await User.find({ _id: { $in: userIds } }).select('name username');
      const uMap = Object.fromEntries(users.map(u => [u._id.toString(), u]));
      const eMap = Object.fromEntries(exams.map(e => [e._id.toString(), e]));

      return res.json(results.map(r => ({
        _id: r._id,
        score: r.score,
        correct: r.correct,
        total: r.total,
        submittedAt: r.submittedAt,
        userName:  uMap[r.userId.toString()]?.name  || 'Không rõ',
        examTitle: eMap[r.examId.toString()]?.title || '—'
      })));
    }
    const results = await Result.find({ userId: req.user.id }).sort({ submittedAt: -1 });
    res.json(results);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/results', auth, async (req, res) => {
  try {
    if (req.user.role !== 'student')
      return res.status(403).json({ error: 'Chỉ học sinh được nộp bài' });

    const { examId, score, correct, total, answers } = req.body;
    const result = await Result.create({
      examId, userId: req.user.id,
      score, correct, total, answers
    });
    res.json(result);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* =========================================================
   SPA FALLBACK — Trả index.html cho mọi route khác
   ========================================================= */
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

/* =========================================================
   START SERVER
   ========================================================= */
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/khaothi';

mongoose.connect(MONGO_URI)
  .then(async () => {
    console.log('✅ Đã kết nối MongoDB');
    await seed();
    app.listen(PORT, () => console.log(`🚀 Server chạy tại http://localhost:${PORT}`));
  })
  .catch(e => {
    console.error('❌ Lỗi kết nối MongoDB:', e.message);
    process.exit(1);
  });