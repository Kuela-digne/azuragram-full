require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const http = require("http");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { Server } = require("socket.io");
const { PrismaClient } = require("@prisma/client");
const rateLimit = require("express-rate-limit");
const { body, validationResult } = require("express-validator");

const prisma = new PrismaClient();
const app = express();
const server = http.createServer(app);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME_SUPER_SECRET";

app.use(helmet());
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: "Trop de tentatives, réessayez plus tard" },
});
app.use("/api/auth/", authLimiter);

app.use(express.static("public"));

function signToken(user) {
  return jwt.sign({ sub: user.id, name: user.name, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
}

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Non autorisé" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Token invalide ou expiré" });
  }
}

app.post("/api/auth/signup", [
  body("name").notEmpty().withMessage("Nom requis"),
  body("email").isEmail().withMessage("Email invalide"),
  body("password").isLength({ min: 8 }).withMessage("Mot de passe trop court (min 8)"),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });
  const { name, email, password } = req.body;
  try {
    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) return res.status(400).json({ error: "Email déjà utilisé" });
    const passwordHash = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({ data: { name, email, passwordHash } });
    const token = signToken(user);
    res.json({ token });
  } catch (e) {
    res.status(500).json({ error: "Erreur serveur" });
  }
});

app.post("/api/auth/login", [
  body("email").isEmail().withMessage("Email invalide"),
  body("password").notEmpty().withMessage("Mot de passe requis"),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });
  const { email, password } = req.body;
  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(401).json({ error: "Identifiants invalides" });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: "Identifiants invalides" });
    const token = signToken(user);
    res.json({ token });
  } catch (e) {
    res.status(500).json({ error: "Erreur serveur" });
  }
});

app.get("/api/me", auth, async (req, res) => {
  const user = await prisma.user.findUnique({ where: { id: req.user.sub } });
  if (!user) return res.status(404).json({ error: "Utilisateur introuvable" });
  res.json({ id: user.id, name: user.name, email: user.email });
});

app.get("/api/chats", auth, async (req, res) => {
  const userId = req.user.sub;
  const chats = await prisma.chat.findMany({
    where: { members: { some: { userId } } },
    orderBy: [{ pinned: "desc" }, { lastMessageAt: "desc" }],
    include: { _count: { select: { members: true } } },
  });
  res.json(chats.map(c => ({
    id: c.id,
    name: c.name,
    type: c.type,
    pinned: c.pinned,
    createdAt: c.createdAt.toISOString(),
    lastMessageAt: c.lastMessageAt ? c.lastMessageAt.toISOString() : null,
    lastMessagePreview: c.lastMessagePreview || "",
    unread: 0,
    membersCount: c._count.members,
  })));
});

app.post("/api/chats", auth, async (req, res) => {
  const userId = req.user.sub;
  const { name, type } = req.body;
  if (!name) return res.status(400).json({ error: "Nom requis" });
  const safeType = ["private", "group", "channel"].includes(type) ? type : "private";
  const chat = await prisma.chat.create({
    data: { name, type: safeType, pinned: false, members: { create: [{ userId, role: "owner" }] } },
    include: { _count: { select: { members: true } } },
  });
  res.json({
    id: chat.id,
    name: chat.name,
    type: chat.type,
    pinned: chat.pinned,
    createdAt: chat.createdAt.toISOString(),
    lastMessageAt: null,
    lastMessagePreview: "",
    unread: 0,
    membersCount: chat._count.members,
  });
});

app.patch("/api/chats/:chatId", auth, async (req, res) => {
  const userId = req.user.sub;
  const { chatId } = req.params;
  const { pinned, name } = req.body;
  const member = await prisma.chatMember.findFirst({ where: { chatId, userId } });
  if (!member) return res.status(403).json({ error: "Accès refusé" });
  const chat = await prisma.chat.update({
    where: { id: chatId },
    data: { pinned: typeof pinned === "boolean" ? pinned : undefined, name: typeof name === "string" ? name : undefined },
    include: { _count: { select: { members: true } } },
  });
  res.json({
    id: chat.id, name: chat.name, type: chat.type, pinned: chat.pinned,
    createdAt: chat.createdAt.toISOString(), lastMessageAt: chat.lastMessageAt?.toISOString() || null,
    lastMessagePreview: chat.lastMessagePreview || "", unread: 0, membersCount: chat._count.members,
  });
});

app.get("/api/chats/:chatId/messages", auth, async (req, res) => {
  const { chatId } = req.params;
  const member = await prisma.chatMember.findFirst({ where: { chatId, userId: req.user.sub } });
  if (!member) return res.status(403).json({ error: "Accès refusé" });
  const before = req.query.before ? new Date(req.query.before) : null;
  const whereClause = { chatId };
  if (before) whereClause.createdAt = { lt: before };
  const msgs = await prisma.message.findMany({
    where: whereClause,
    orderBy: { createdAt: "asc" },
    take: 30,
    include: { sender: true },
  });
  res.json(msgs.map(m => ({
    id: m.id, chatId: m.chatId, senderId: m.senderId, senderName: m.sender.name,
    text: m.text, createdAt: m.createdAt.toISOString(), editedAt: m.editedAt?.toISOString() || null,
  })));
});

app.post("/api/chats/:chatId/messages", auth, async (req, res) => {
  const { chatId } = req.params;
  const { text } = req.body;
  if (!text || !text.trim()) return res.status(400).json({ error: "Message vide" });
  const member = await prisma.chatMember.findFirst({ where: { chatId, userId: req.user.sub } });
  if (!member) return res.status(403).json({ error: "Accès refusé" });
  const msg = await prisma.message.create({
    data: { chatId, senderId: req.user.sub, text: text.trim() },
    include: { sender: true },
  });
  const payload = {
    id: msg.id, chatId: msg.chatId, senderId: msg.senderId, senderName: msg.sender.name,
    text: msg.text, createdAt: msg.createdAt.toISOString(), editedAt: null,
  };
  await prisma.chat.update({
    where: { id: chatId },
    data: { lastMessageAt: msg.createdAt, lastMessagePreview: msg.text.slice(0, 180) },
  });
  io.to("chat:" + chatId).emit("message:new", payload);
  res.json(payload);
});

app.put("/api/chats/:chatId/messages/:messageId", auth, async (req, res) => {
  const { chatId, messageId } = req.params;
  const { text } = req.body;
  const msg = await prisma.message.findUnique({ where: { id: messageId } });
  if (!msg || msg.chatId !== chatId) return res.status(404).json({ error: "Message introuvable" });
  if (msg.senderId !== req.user.sub) return res.status(403).json({ error: "Non autorisé" });
  const updated = await prisma.message.update({
    where: { id: messageId },
    data: { text: text.trim(), editedAt: new Date() },
    include: { sender: true },
  });
  const payload = {
    id: updated.id, chatId: updated.chatId, senderId: updated.senderId, senderName: updated.sender.name,
    text: updated.text, createdAt: updated.createdAt.toISOString(), editedAt: updated.editedAt.toISOString(),
  };
  io.to("chat:" + chatId).emit("message:updated", payload);
  res.json(payload);
});

app.delete("/api/chats/:chatId/messages/:messageId", auth, async (req, res) => {
  const { chatId, messageId } = req.params;
  const msg = await prisma.message.findUnique({ where: { id: messageId } });
  if (!msg || msg.chatId !== chatId) return res.status(404).json({ error: "Message introuvable" });
  if (msg.senderId !== req.user.sub) return res.status(403).json({ error: "Non autorisé" });
  await prisma.message.delete({ where: { id: messageId } });
  io.to("chat:" + chatId).emit("message:deleted", { id: messageId, chatId });
  res.json({ success: true });
});

const io = new Server(server, { cors: { origin: true, credentials: true } });
io.use(async (socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error("Auth requise"));
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    socket.user = payload;
    next();
  } catch (e) { next(new Error("Token invalide")); }
});

const typingUsers = new Map();
io.on("connection", (socket) => {
  socket.on("chat:join", async ({ chatId }) => {
    const member = await prisma.chatMember.findFirst({ where: { chatId, userId: socket.user.sub } });
    if (!member) return;
    socket.join("chat:" + chatId);
  });
  socket.on("typing:start", ({ chatId }) => {
    if (!typingUsers.has(chatId)) typingUsers.set(chatId, new Set());
    typingUsers.get(chatId).add(socket.user.name);
    io.to("chat:" + chatId).emit("typing:update", Array.from(typingUsers.get(chatId)));
  });
  socket.on("typing:stop", ({ chatId }) => {
    const set = typingUsers.get(chatId);
    if (set) { set.delete(socket.user.name); io.to("chat:" + chatId).emit("typing:update", Array.from(set)); }
  });
  socket.on("disconnect", () => {
    for (const [chatId, users] of typingUsers.entries()) {
      users.delete(socket.user.name);
      io.to("chat:" + chatId).emit("typing:update", Array.from(users));
    }
  });
});

server.listen(PORT, () => console.log(`AzuraGram server on port ${PORT}`));
