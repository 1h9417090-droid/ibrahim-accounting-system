// server/index.ts
import express2 from "express";

// server/routes.ts
import { createServer } from "http";

// shared/schema.ts
import mongoose, { Schema } from "mongoose";
import { z } from "zod";
var connectDB = async () => {
  try {
    const mongoURI = process.env.MONGODB_URI || "mongodb+srv://sehx0190_db_user:Sanad$sa19971997@cluster0.yselhek.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
    await mongoose.connect(mongoURI);
    console.log("MongoDB connected successfully");
  } catch (error) {
    console.error("MongoDB connection error:", error);
    process.exit(1);
  }
};
var UserRole = {
  SUPER_ADMIN: "super_admin",
  OWNER: "owner",
  MANAGER: "manager",
  ACCOUNTANT: "accountant",
  WAREHOUSE_KEEPER: "warehouse_keeper",
  VIEWER: "viewer"
};
var Currency = {
  SYP: "SYP",
  // Syrian Pound
  TRY: "TRY",
  // Turkish Lira
  USD: "USD"
  // US Dollar
};
var TransactionType = {
  SALE: "sale",
  SERVICE: "service",
  ADVANCE_PAYMENT: "advance_payment",
  OTHER: "other"
};
var PaymentMethod = {
  CASH: "cash",
  CARD: "card",
  TRANSFER: "transfer",
  OTHER: "other"
};
var ExpenseType = {
  RENT: "rent",
  SALARIES: "salaries",
  SERVICES: "services",
  PURCHASE: "purchase",
  UTILITIES: "utilities",
  MAINTENANCE: "maintenance",
  OTHER: "other"
};
var UserSchema = new Schema({
  username: { type: String, required: true, unique: true, maxlength: 50 },
  email: { type: String, unique: true, sparse: true },
  password: { type: String, required: true },
  firstName: { type: String, maxlength: 50 },
  lastName: { type: String, maxlength: 50 },
  role: {
    type: String,
    required: true,
    enum: Object.values(UserRole),
    default: UserRole.VIEWER
  },
  isActive: { type: Boolean, required: true, default: true },
  tenantId: { type: String, required: true },
  profileImageUrl: String
}, {
  timestamps: true
});
var TenantSchema = new Schema({
  name: { type: String, required: true, maxlength: 100 },
  subscriptionExpiresAt: { type: Date, required: true },
  isActive: { type: Boolean, required: true, default: true }
}, {
  timestamps: true
});
var ProductSchema = new Schema({
  name: { type: String, required: true, maxlength: 100 },
  category: { type: String, maxlength: 50 },
  unit: { type: String, required: true, maxlength: 20 },
  quantity: { type: Number, required: true, default: 0 },
  purchasePrice: { type: Number, required: true },
  salePrice: { type: Number, required: true },
  supplier: { type: String, maxlength: 100 },
  minStockLevel: { type: Number, required: true, default: 0 },
  tenantId: { type: String, required: true }
}, {
  timestamps: true
});
var RevenueSchema = new Schema({
  operationNumber: { type: String, required: true, maxlength: 20 },
  customerName: { type: String, maxlength: 100 },
  transactionType: {
    type: String,
    required: true,
    enum: Object.values(TransactionType)
  },
  productService: { type: String, required: true, maxlength: 100 },
  quantity: { type: Number, required: true, default: 1 },
  unitPrice: { type: Number, required: true },
  totalAmount: { type: Number, required: true },
  currency: {
    type: String,
    required: true,
    enum: Object.values(Currency)
  },
  paymentMethod: {
    type: String,
    required: true,
    enum: Object.values(PaymentMethod)
  },
  notes: String,
  tenantId: { type: String, required: true },
  createdBy: { type: String, required: true }
}, {
  timestamps: true
});
var ExpenseSchema = new Schema({
  operationNumber: { type: String, required: true, maxlength: 20 },
  supplierName: { type: String, maxlength: 100 },
  expenseType: {
    type: String,
    required: true,
    enum: Object.values(ExpenseType)
  },
  description: { type: String, required: true, maxlength: 200 },
  amount: { type: Number, required: true },
  currency: {
    type: String,
    required: true,
    enum: Object.values(Currency)
  },
  paymentMethod: {
    type: String,
    required: true,
    enum: Object.values(PaymentMethod)
  },
  notes: String,
  tenantId: { type: String, required: true },
  createdBy: { type: String, required: true }
}, {
  timestamps: true
});
var NotificationSchema = new Schema({
  title: { type: String, required: true, maxlength: 100 },
  message: { type: String, required: true },
  type: { type: String, required: true, maxlength: 20 },
  isRead: { type: Boolean, required: true, default: false },
  tenantId: { type: String, required: true }
}, {
  timestamps: { createdAt: true, updatedAt: false }
});
UserSchema.index({ tenantId: 1 });
TenantSchema.index({ subscriptionExpiresAt: 1 });
ProductSchema.index({ tenantId: 1 });
ProductSchema.index({ quantity: 1 });
RevenueSchema.index({ tenantId: 1 });
RevenueSchema.index({ createdAt: -1 });
ExpenseSchema.index({ tenantId: 1 });
ExpenseSchema.index({ createdAt: -1 });
NotificationSchema.index({ tenantId: 1 });
NotificationSchema.index({ isRead: 1 });
var User = mongoose.model("User", UserSchema);
var Tenant = mongoose.model("Tenant", TenantSchema);
var Product = mongoose.model("Product", ProductSchema);
var Revenue = mongoose.model("Revenue", RevenueSchema);
var Expense = mongoose.model("Expense", ExpenseSchema);
var Notification = mongoose.model("Notification", NotificationSchema);
var insertUserSchema = z.object({
  username: z.string().min(1).max(50),
  email: z.string().email().optional(),
  password: z.string().min(6),
  firstName: z.string().max(50).optional(),
  lastName: z.string().max(50).optional(),
  role: z.enum(Object.values(UserRole)),
  isActive: z.boolean().default(true),
  tenantId: z.string(),
  profileImageUrl: z.string().optional()
});
var insertTenantSchema = z.object({
  name: z.string().min(1).max(100),
  subscriptionExpiresAt: z.date(),
  isActive: z.boolean().default(true)
});
var insertProductSchema = z.object({
  name: z.string().min(1).max(100),
  category: z.string().max(50).optional(),
  unit: z.string().min(1).max(20),
  quantity: z.number().min(0),
  purchasePrice: z.number().positive(),
  salePrice: z.number().positive(),
  supplier: z.string().max(100).optional(),
  minStockLevel: z.number().min(0).default(0),
  tenantId: z.string()
});
var insertRevenueSchema = z.object({
  customerName: z.string().max(100).optional(),
  transactionType: z.enum(Object.values(TransactionType)),
  productService: z.string().min(1).max(100),
  quantity: z.number().min(1).default(1),
  unitPrice: z.number().positive(),
  totalAmount: z.number().positive(),
  currency: z.enum(Object.values(Currency)),
  paymentMethod: z.enum(Object.values(PaymentMethod)),
  notes: z.string().optional(),
  tenantId: z.string(),
  createdBy: z.string()
});
var insertExpenseSchema = z.object({
  supplierName: z.string().max(100).optional(),
  expenseType: z.enum(Object.values(ExpenseType)),
  description: z.string().min(1).max(200),
  amount: z.number().positive(),
  currency: z.enum(Object.values(Currency)),
  paymentMethod: z.enum(Object.values(PaymentMethod)),
  notes: z.string().optional(),
  tenantId: z.string(),
  createdBy: z.string()
});
var insertNotificationSchema = z.object({
  title: z.string().min(1).max(100),
  message: z.string().min(1),
  type: z.string().min(1).max(20),
  isRead: z.boolean().default(false),
  tenantId: z.string()
});

// server/storage.ts
var generateOperationNumber = (prefix) => {
  const timestamp = Date.now().toString().slice(-8);
  const random = Math.random().toString(36).substring(2, 6).toUpperCase();
  return `${prefix}${timestamp}${random}`;
};
var storage = {
  // User operations
  async getUserByUsername(username) {
    return await User.findOne({ username, isActive: true });
  },
  async getUser(id) {
    return await User.findById(id);
  },
  async createUser(userData) {
    const user = new User(userData);
    return await user.save();
  },
  async updateUser(id, userData) {
    return await User.findByIdAndUpdate(id, userData, { new: true });
  },
  async deleteUser(id) {
    return await User.findByIdAndUpdate(id, { isActive: false }, { new: true });
  },
  async getUsers(tenantId) {
    return await User.find({ tenantId, isActive: true }).select("-password");
  },
  // Tenant operations
  async getTenant(id) {
    return await Tenant.findById(id);
  },
  async createTenant(tenantData) {
    const tenant = new Tenant(tenantData);
    return await tenant.save();
  },
  async updateTenant(id, tenantData) {
    return await Tenant.findByIdAndUpdate(id, tenantData, { new: true });
  },
  // Product operations
  async getProducts(tenantId) {
    return await Product.find({ tenantId }).sort({ createdAt: -1 });
  },
  async createProduct(productData) {
    const product = new Product(productData);
    return await product.save();
  },
  async updateProduct(id, productData) {
    return await Product.findByIdAndUpdate(id, productData, { new: true });
  },
  async deleteProduct(id, tenantId) {
    return await Product.findOneAndDelete({ _id: id, tenantId });
  },
  async getLowStockProducts(tenantId) {
    return await Product.find({
      tenantId,
      $expr: { $lte: ["$quantity", "$minStockLevel"] }
    });
  },
  // Revenue operations
  async getRevenues(tenantId, limit = 50) {
    return await Revenue.find({ tenantId }).sort({ createdAt: -1 }).limit(limit);
  },
  async createRevenue(revenueData) {
    const operationNumber = generateOperationNumber("REV");
    const revenue = new Revenue({ ...revenueData, operationNumber });
    return await revenue.save();
  },
  async updateRevenue(id, revenueData) {
    return await Revenue.findByIdAndUpdate(id, revenueData, { new: true });
  },
  async deleteRevenue(id, tenantId) {
    return await Revenue.findOneAndDelete({ _id: id, tenantId });
  },
  // Expense operations
  async getExpenses(tenantId, limit = 50) {
    return await Expense.find({ tenantId }).sort({ createdAt: -1 }).limit(limit);
  },
  async createExpense(expenseData) {
    const operationNumber = generateOperationNumber("EXP");
    const expense = new Expense({ ...expenseData, operationNumber });
    return await expense.save();
  },
  async updateExpense(id, expenseData) {
    return await Expense.findByIdAndUpdate(id, expenseData, { new: true });
  },
  async deleteExpense(id, tenantId) {
    return await Expense.findOneAndDelete({ _id: id, tenantId });
  },
  // Notification operations
  async getNotifications(tenantId, limit = 20) {
    return await Notification.find({ tenantId }).sort({ createdAt: -1 }).limit(limit);
  },
  async createNotification(notificationData) {
    const notification = new Notification(notificationData);
    return await notification.save();
  },
  async markNotificationAsRead(id, tenantId) {
    return await Notification.findOneAndUpdate(
      { _id: id, tenantId },
      { isRead: true },
      { new: true }
    );
  },
  async getUnreadNotificationCount(tenantId) {
    return await Notification.countDocuments({ tenantId, isRead: false });
  },
  // Dashboard operations
  async getDashboardStats(tenantId) {
    const [revenues, expenses] = await Promise.all([
      Revenue.aggregate([
        { $match: { tenantId } },
        { $group: { _id: null, total: { $sum: "$totalAmount" } } }
      ]),
      Expense.aggregate([
        { $match: { tenantId } },
        { $group: { _id: null, total: { $sum: "$amount" } } }
      ])
    ]);
    const totalRevenue = revenues[0]?.total || 0;
    const totalExpenses = expenses[0]?.total || 0;
    const netProfit = totalRevenue - totalExpenses;
    return {
      totalRevenue,
      totalExpenses,
      netProfit,
      totalProducts: await Product.countDocuments({ tenantId }),
      lowStockProducts: await Product.countDocuments({
        tenantId,
        $expr: { $lte: ["$quantity", "$minStockLevel"] }
      })
    };
  },
  async getRecentTransactions(tenantId, limit = 10) {
    const [revenues, expenses] = await Promise.all([
      Revenue.find({ tenantId }).sort({ createdAt: -1 }).limit(limit).lean(),
      Expense.find({ tenantId }).sort({ createdAt: -1 }).limit(limit).lean()
    ]);
    const transactions = [
      ...revenues.map((r) => ({ ...r, type: "revenue" })),
      ...expenses.map((e) => ({ ...e, type: "expense" }))
    ];
    return transactions.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()).slice(0, limit);
  },
  async getCurrencyDistribution(tenantId) {
    const [revenueDistribution, expenseDistribution] = await Promise.all([
      Revenue.aggregate([
        { $match: { tenantId } },
        { $group: { _id: "$currency", total: { $sum: "$totalAmount" } } }
      ]),
      Expense.aggregate([
        { $match: { tenantId } },
        { $group: { _id: "$currency", total: { $sum: "$amount" } } }
      ])
    ]);
    const currencies = Object.values(Currency);
    const distribution = currencies.map((currency) => {
      const revenue = revenueDistribution.find((r) => r._id === currency)?.total || 0;
      const expense = expenseDistribution.find((e) => e._id === currency)?.total || 0;
      return {
        currency,
        revenue,
        expense,
        net: revenue - expense
      };
    });
    return distribution;
  },
  async getMonthlyRevenueData(tenantId, year) {
    const startDate = new Date(year, 0, 1);
    const endDate = new Date(year, 11, 31, 23, 59, 59);
    const monthlyData = await Revenue.aggregate([
      {
        $match: {
          tenantId,
          createdAt: { $gte: startDate, $lte: endDate }
        }
      },
      {
        $group: {
          _id: { $month: "$createdAt" },
          total: { $sum: "$totalAmount" },
          count: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);
    const months = Array.from({ length: 12 }, (_, i) => i + 1);
    return months.map((month) => {
      const data = monthlyData.find((d) => d._id === month);
      return {
        month,
        total: data?.total || 0,
        count: data?.count || 0
      };
    });
  }
};

// server/routes.ts
import bcrypt from "bcrypt";
import session from "express-session";
import { z as z2 } from "zod";

// server/types.ts
import "express-session";

// server/routes.ts
var sessionConfig = session({
  secret: process.env.SESSION_SECRET || "accounting-system-secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === "production",
    // true in production
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1e3,
    // 24 hours
    sameSite: "none",
    // required for cross-origin
    domain: process.env.NODE_ENV === "production" ? ".netlify.app" : void 0
    // allow cookies across subdomains
  }
});
var requireAuth = (req, res, next) => {
  if (!req.session?.user) {
    return res.status(401).json({ message: "Authentication required" });
  }
  next();
};
var requirePermission = (permissions) => {
  return (req, res, next) => {
    const userRole = req.session?.user?.role;
    if (!userRole || !permissions.includes(userRole)) {
      return res.status(403).json({ message: "Insufficient permissions" });
    }
    next();
  };
};
async function registerRoutes(app2) {
  app2.use(sessionConfig);
  app2.post("/api/auth/login", async (req, res) => {
    try {
      const { username, password } = req.body;
      if (!username || !password) {
        return res.status(400).json({ message: "Username and password required" });
      }
      const user = await storage.getUserByUsername(username);
      if (!user || !user.isActive) {
        return res.status(401).json({ message: "Invalid credentials" });
      }
      const isValidPassword = await bcrypt.compare(password, user.password);
      if (!isValidPassword) {
        return res.status(401).json({ message: "Invalid credentials" });
      }
      const tenant = await storage.getTenant(user.tenantId);
      if (!tenant || !tenant.isActive || tenant.subscriptionExpiresAt < /* @__PURE__ */ new Date()) {
        return res.status(403).json({ message: "Subscription expired or inactive" });
      }
      req.session.user = {
        id: user.id,
        username: user.username,
        role: user.role,
        tenantId: user.tenantId,
        firstName: user.firstName || void 0,
        lastName: user.lastName || void 0
      };
      res.json({
        user: req.session.user,
        tenant: {
          id: tenant.id,
          name: tenant.name,
          subscriptionExpiresAt: tenant.subscriptionExpiresAt
        }
      });
    } catch (error) {
      console.error("Login error:", error);
      res.status(500).json({ message: "Login failed" });
    }
  });
  app2.post("/api/auth/logout", (req, res) => {
    req.session.destroy((err) => {
      if (err) {
        return res.status(500).json({ message: "Logout failed" });
      }
      res.json({ message: "Logged out successfully" });
    });
  });
  app2.get("/api/auth/user", async (req, res) => {
    try {
      if (!req.session?.user) {
        return res.status(401).json({ message: "Authentication required" });
      }
      const user = await storage.getUser(req.session.user.id);
      const tenant = await storage.getTenant(req.session.user.tenantId);
      res.json({
        user: {
          id: user?.id,
          username: user?.username,
          role: user?.role,
          firstName: user?.firstName,
          lastName: user?.lastName,
          email: user?.email,
          isActive: user?.isActive,
          tenantId: user?.tenantId
        },
        tenant: {
          id: tenant?.id,
          name: tenant?.name,
          subscriptionExpiresAt: tenant?.subscriptionExpiresAt
        }
      });
    } catch (error) {
      console.error("Get user error:", error);
      res.status(500).json({ message: "Failed to get user" });
    }
  });
  app2.get("/api/dashboard/stats", requireAuth, async (req, res) => {
    try {
      const stats = await storage.getDashboardStats(req.session.user.tenantId);
      const notifications = await storage.getUnreadNotificationCount(req.session.user.tenantId);
      res.json({ ...stats, unreadNotifications: notifications });
    } catch (error) {
      console.error("Dashboard stats error:", error);
      res.status(500).json({ message: "Failed to get dashboard stats" });
    }
  });
  app2.get("/api/dashboard/recent-transactions", requireAuth, async (req, res) => {
    try {
      const limit = parseInt(req.query.limit) || 10;
      const transactions = await storage.getRecentTransactions(req.session.user.tenantId, limit);
      res.json(transactions);
    } catch (error) {
      console.error("Recent transactions error:", error);
      res.status(500).json({ message: "Failed to get recent transactions" });
    }
  });
  app2.get("/api/dashboard/currency-distribution", requireAuth, async (req, res) => {
    try {
      const distribution = await storage.getCurrencyDistribution(req.session.user.tenantId);
      res.json(distribution);
    } catch (error) {
      console.error("Currency distribution error:", error);
      res.status(500).json({ message: "Failed to get currency distribution" });
    }
  });
  app2.get("/api/dashboard/monthly-revenue", requireAuth, async (req, res) => {
    try {
      const year = parseInt(req.query.year) || (/* @__PURE__ */ new Date()).getFullYear();
      const monthlyData = await storage.getMonthlyRevenueData(req.session.user.tenantId, year);
      res.json(monthlyData);
    } catch (error) {
      console.error("Monthly revenue error:", error);
      res.status(500).json({ message: "Failed to get monthly revenue" });
    }
  });
  app2.get("/api/revenues", requireAuth, async (req, res) => {
    try {
      const limit = parseInt(req.query.limit) || 50;
      const revenues = await storage.getRevenues(req.session.user.tenantId, limit);
      res.json(revenues);
    } catch (error) {
      console.error("Get revenues error:", error);
      res.status(500).json({ message: "Failed to get revenues" });
    }
  });
  app2.post(
    "/api/revenues",
    requireAuth,
    requirePermission(["super_admin", "owner", "manager", "accountant"]),
    async (req, res) => {
      try {
        const validatedData = insertRevenueSchema.parse({
          ...req.body,
          tenantId: req.session.user.tenantId,
          createdBy: req.session.user.id
        });
        const revenue = await storage.createRevenue(validatedData);
        res.status(201).json(revenue);
      } catch (error) {
        if (error instanceof z2.ZodError) {
          return res.status(400).json({ message: "Validation error", errors: error.errors });
        }
        console.error("Create revenue error:", error);
        res.status(500).json({ message: "Failed to create revenue" });
      }
    }
  );
  app2.put(
    "/api/revenues/:id",
    requireAuth,
    requirePermission(["super_admin", "owner", "manager", "accountant"]),
    async (req, res) => {
      try {
        const { id } = req.params;
        const validatedData = insertRevenueSchema.partial().parse(req.body);
        const revenue = await storage.updateRevenue(id, validatedData);
        res.json(revenue);
      } catch (error) {
        if (error instanceof z2.ZodError) {
          return res.status(400).json({ message: "Validation error", errors: error.errors });
        }
        console.error("Update revenue error:", error);
        res.status(500).json({ message: "Failed to update revenue" });
      }
    }
  );
  app2.delete(
    "/api/revenues/:id",
    requireAuth,
    requirePermission(["super_admin", "owner", "manager", "accountant"]),
    async (req, res) => {
      try {
        const { id } = req.params;
        await storage.deleteRevenue(id, req.session.user.tenantId);
        res.json({ message: "Revenue deleted successfully" });
      } catch (error) {
        console.error("Delete revenue error:", error);
        res.status(500).json({ message: "Failed to delete revenue" });
      }
    }
  );
  app2.get("/api/expenses", requireAuth, async (req, res) => {
    try {
      const limit = parseInt(req.query.limit) || 50;
      const expenses = await storage.getExpenses(req.session.user.tenantId, limit);
      res.json(expenses);
    } catch (error) {
      console.error("Get expenses error:", error);
      res.status(500).json({ message: "Failed to get expenses" });
    }
  });
  app2.post(
    "/api/expenses",
    requireAuth,
    requirePermission(["super_admin", "owner", "manager", "accountant"]),
    async (req, res) => {
      try {
        const validatedData = insertExpenseSchema.parse({
          ...req.body,
          tenantId: req.session.user.tenantId,
          createdBy: req.session.user.id
        });
        const expense = await storage.createExpense(validatedData);
        res.status(201).json(expense);
      } catch (error) {
        if (error instanceof z2.ZodError) {
          return res.status(400).json({ message: "Validation error", errors: error.errors });
        }
        console.error("Create expense error:", error);
        res.status(500).json({ message: "Failed to create expense" });
      }
    }
  );
  app2.put(
    "/api/expenses/:id",
    requireAuth,
    requirePermission(["super_admin", "owner", "manager", "accountant"]),
    async (req, res) => {
      try {
        const { id } = req.params;
        const validatedData = insertExpenseSchema.partial().parse(req.body);
        const expense = await storage.updateExpense(id, validatedData);
        res.json(expense);
      } catch (error) {
        if (error instanceof z2.ZodError) {
          return res.status(400).json({ message: "Validation error", errors: error.errors });
        }
        console.error("Update expense error:", error);
        res.status(500).json({ message: "Failed to update expense" });
      }
    }
  );
  app2.delete(
    "/api/expenses/:id",
    requireAuth,
    requirePermission(["super_admin", "owner", "manager", "accountant"]),
    async (req, res) => {
      try {
        const { id } = req.params;
        await storage.deleteExpense(id, req.session.user.tenantId);
        res.json({ message: "Expense deleted successfully" });
      } catch (error) {
        console.error("Delete expense error:", error);
        res.status(500).json({ message: "Failed to delete expense" });
      }
    }
  );
  app2.get("/api/products", requireAuth, async (req, res) => {
    try {
      const products = await storage.getProducts(req.session.user.tenantId);
      res.json(products);
    } catch (error) {
      console.error("Get products error:", error);
      res.status(500).json({ message: "Failed to get products" });
    }
  });
  app2.post(
    "/api/products",
    requireAuth,
    requirePermission(["super_admin", "owner", "manager", "warehouse_keeper"]),
    async (req, res) => {
      try {
        const validatedData = insertProductSchema.parse({
          ...req.body,
          tenantId: req.session.user.tenantId
        });
        const product = await storage.createProduct(validatedData);
        res.status(201).json(product);
      } catch (error) {
        if (error instanceof z2.ZodError) {
          return res.status(400).json({ message: "Validation error", errors: error.errors });
        }
        console.error("Create product error:", error);
        res.status(500).json({ message: "Failed to create product" });
      }
    }
  );
  app2.put(
    "/api/products/:id",
    requireAuth,
    requirePermission(["super_admin", "owner", "manager", "warehouse_keeper"]),
    async (req, res) => {
      try {
        const { id } = req.params;
        const validatedData = insertProductSchema.partial().parse(req.body);
        const product = await storage.updateProduct(id, validatedData);
        res.json(product);
      } catch (error) {
        if (error instanceof z2.ZodError) {
          return res.status(400).json({ message: "Validation error", errors: error.errors });
        }
        console.error("Update product error:", error);
        res.status(500).json({ message: "Failed to update product" });
      }
    }
  );
  app2.delete(
    "/api/products/:id",
    requireAuth,
    requirePermission(["super_admin", "owner", "manager"]),
    async (req, res) => {
      try {
        const { id } = req.params;
        await storage.deleteProduct(id, req.session.user.tenantId);
        res.json({ message: "Product deleted successfully" });
      } catch (error) {
        console.error("Delete product error:", error);
        res.status(500).json({ message: "Failed to delete product" });
      }
    }
  );
  app2.get("/api/products/low-stock", requireAuth, async (req, res) => {
    try {
      const products = await storage.getLowStockProducts(req.session.user.tenantId);
      res.json(products);
    } catch (error) {
      console.error("Get low stock products error:", error);
      res.status(500).json({ message: "Failed to get low stock products" });
    }
  });
  app2.get("/api/notifications", requireAuth, async (req, res) => {
    try {
      const limit = parseInt(req.query.limit) || 20;
      const notifications = await storage.getNotifications(req.session.user.tenantId, limit);
      res.json(notifications);
    } catch (error) {
      console.error("Get notifications error:", error);
      res.status(500).json({ message: "Failed to get notifications" });
    }
  });
  app2.post(
    "/api/notifications",
    requireAuth,
    requirePermission(["super_admin", "owner", "manager"]),
    async (req, res) => {
      try {
        const validatedData = insertNotificationSchema.parse({
          ...req.body,
          tenantId: req.session.user.tenantId
        });
        const notification = await storage.createNotification(validatedData);
        res.status(201).json(notification);
      } catch (error) {
        if (error instanceof z2.ZodError) {
          return res.status(400).json({ message: "Validation error", errors: error.errors });
        }
        console.error("Create notification error:", error);
        res.status(500).json({ message: "Failed to create notification" });
      }
    }
  );
  app2.put(
    "/api/notifications/:id/read",
    requireAuth,
    async (req, res) => {
      try {
        const { id } = req.params;
        await storage.markNotificationAsRead(id, req.session.user.tenantId);
        res.json({ message: "Notification marked as read" });
      } catch (error) {
        console.error("Mark notification as read error:", error);
        res.status(500).json({ message: "Failed to mark notification as read" });
      }
    }
  );
  app2.get("/api/users", requireAuth, async (req, res) => {
    try {
      const users = await storage.getUsers(req.session.user.tenantId);
      res.json(users);
    } catch (error) {
      console.error("Get users error:", error);
      res.status(500).json({ message: "Failed to get users" });
    }
  });
  app2.post(
    "/api/users",
    requireAuth,
    requirePermission(["super_admin", "owner"]),
    async (req, res) => {
      try {
        const validatedData = insertUserSchema.parse({
          ...req.body,
          tenantId: req.session.user.tenantId
        });
        const user = await storage.createUser(validatedData);
        res.status(201).json(user);
      } catch (error) {
        if (error instanceof z2.ZodError) {
          return res.status(400).json({ message: "Validation error", errors: error.errors });
        }
        console.error("Create user error:", error);
        res.status(500).json({ message: "Failed to create user" });
      }
    }
  );
  app2.put(
    "/api/users/:id",
    requireAuth,
    requirePermission(["super_admin", "owner"]),
    async (req, res) => {
      try {
        const { id } = req.params;
        const validatedData = insertUserSchema.partial().parse(req.body);
        const user = await storage.updateUser(id, validatedData);
        res.json(user);
      } catch (error) {
        if (error instanceof z2.ZodError) {
          return res.status(400).json({ message: "Validation error", errors: error.errors });
        }
        console.error("Update user error:", error);
        res.status(500).json({ message: "Failed to update user" });
      }
    }
  );
  app2.delete(
    "/api/users/:id",
    requireAuth,
    requirePermission(["super_admin", "owner"]),
    async (req, res) => {
      try {
        const { id } = req.params;
        await storage.deleteUser(id, req.session.user.tenantId);
        res.json({ message: "User deleted successfully" });
      } catch (error) {
        console.error("Delete user error:", error);
        res.status(500).json({ message: "Failed to delete user" });
      }
    }
  );
  const httpServer = createServer(app2);
  return httpServer;
}

// server/vite.ts
import express from "express";
import fs from "fs";
import path2 from "path";
import { createServer as createViteServer, createLogger } from "vite";

// vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";
import { fileURLToPath } from "url";
var __dirname = path.dirname(fileURLToPath(import.meta.url));
var vite_config_default = defineConfig({
  plugins: [react()],
  root: path.resolve(__dirname, "client"),
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "client/src"),
      "@shared": path.resolve(__dirname, "shared")
    }
  },
  build: {
    outDir: path.resolve(__dirname, "dist"),
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ["react", "react-dom"],
          ui: ["@radix-ui/react-dialog", "@radix-ui/react-dropdown-menu", "@radix-ui/react-select"]
        }
      }
    }
  },
  server: {
    port: 3e3,
    host: true
  },
  preview: {
    port: 3e3,
    host: true
  }
});

// server/vite.ts
import { nanoid } from "nanoid";
var viteLogger = createLogger();
function log(message, source = "express") {
  const formattedTime = (/* @__PURE__ */ new Date()).toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true
  });
  console.log(`${formattedTime} [${source}] ${message}`);
}
async function setupVite(app2, server) {
  const serverOptions = {
    middlewareMode: true,
    hmr: { server },
    allowedHosts: true
  };
  const vite = await createViteServer({
    ...vite_config_default,
    configFile: false,
    customLogger: {
      ...viteLogger,
      error: (msg, options) => {
        viteLogger.error(msg, options);
        process.exit(1);
      }
    },
    server: serverOptions,
    appType: "custom"
  });
  app2.use(vite.middlewares);
  app2.use("*", async (req, res, next) => {
    const url = req.originalUrl;
    try {
      const clientTemplate = path2.resolve(
        import.meta.dirname,
        "..",
        "client",
        "index.html"
      );
      let template = await fs.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid()}"`
      );
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e);
      next(e);
    }
  });
}
function serveStatic(app2) {
  const distPath = path2.resolve(import.meta.dirname, "public");
  if (!fs.existsSync(distPath)) {
    throw new Error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }
  app2.use(express.static(distPath));
  app2.use("*", (_req, res) => {
    res.sendFile(path2.resolve(distPath, "index.html"));
  });
}

// server/db.ts
var initializeDatabase = async () => {
  await connectDB();
};

// server/index.ts
import cors from "cors";
var app = express2();
app.use(cors({
  origin: ["https://saasaas2.netlify.app", "http://localhost:3000", "http://127.0.0.1:3000"],
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express2.json());
app.use(express2.urlencoded({ extended: false }));
app.use((req, res, next) => {
  const start = Date.now();
  const path3 = req.path;
  let capturedJsonResponse = void 0;
  const originalResJson = res.json;
  res.json = function(bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };
  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path3.startsWith("/api")) {
      let logLine = `${req.method} ${path3} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }
      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "\u2026";
      }
      log(logLine);
    }
  });
  next();
});
(async () => {
  await initializeDatabase();
  const server = await registerRoutes(app);
  app.use((err, _req, res, _next) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";
    res.status(status).json({ message });
    throw err;
  });
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }
  const port = parseInt(process.env.PORT || "3000", 10);
  server.listen({
    port,
    host: "0.0.0.0"
  }, () => {
    log(`serving on port ${port}`);
  });
})();
