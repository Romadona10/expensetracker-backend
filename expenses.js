const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const router = express.Router();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({
  origin: ['http://localhost:4200', 'https://romadona10.github.io'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true
}));

// MongoDB connection
const mongoURI = process.env.MONGODB_URI || "mongodb+srv://okekekingsley558:8QCcO0urfRwFEtJR@flightsdb.tad5zfd.mongodb.net/?retryWrites=true&w=majority&appName=flightsdb";

mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(async () => {
    console.log('MongoDB connected');

    const adminUser = await User.findOne({ email: process.env.ADMIN_EMAIL });
    if (!adminUser) {
      const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD, 8);
      const newAdmin = new User({ 
        fullName: 'Admin User',
        email: process.env.ADMIN_EMAIL,
        password: hashedPassword,
        isAdmin: true
      });
      await newAdmin.save();
      console.log('Admin user created');
    } else {
      console.log('Admin user already exists');
    }
  })
  .catch((err) => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

// User model
const UserSchema = new mongoose.Schema({
  fullName: String,
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  picture: String,
  isAdmin: { type: Boolean, default: false },
  isActive: { type: Boolean, default: true },
  picture: { type: String }
});

const User = mongoose.model('User', UserSchema);

const ExpenseSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  date: { type: Date, required: true },
  amount: { type: Number, required: true },
  description: String,
  category: String
});
const Expense = mongoose.model('Expense', ExpenseSchema);

// UserSettings model
const UserSettingsSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  currency: { type: String, default: '$' },
  notifications: { type: Boolean, default: true },
  reminderFrequency: { type: String, enum: ['daily', 'weekly', 'monthly'], default: 'daily' },
  userBudget:{type: Number,default:1000000}
});

const UserSettings = mongoose.model('UserSettings', UserSettingsSchema);


// Ensure uploads directory exists
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Category model
const CategorySchema = new mongoose.Schema({
  name: { type: String, required: true },
});
const Category = mongoose.model('Category', CategorySchema);

// Configure multer for image upload
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  },
});

const upload = multer({ storage });



 

// User Registration
app.post('/api/auth/register', upload.single('picture'), async (req, res) => {
  const { fullName, email, password } = req.body;
  
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.status(400).json({ message: 'Email already registered' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const picture = req.file ? req.file.filename : null;

  const user = new User({ fullName, email, password: hashedPassword, picture });
  await user.save();
  res.status(201).json({ message: 'User registered successfully' });
});

// User Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: 'Invalid credentials' });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

  const token = jwt.sign({ userId: user._id, isAdmin: user.isAdmin }, process.env.JWT_SECRET || 'your_jwt_secret_here', { expiresIn: '1h' });
  res.json({ token, isAdmin: user.isAdmin, userId: user._id ,picture: user.picture});
 
});

// Complete Delete User Account
app.delete('/api/auth/delete/:id', async (req, res) => {
  const userId = req.params.id;

  try {
    const user = await User.findByIdAndDelete(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.status(200).json({ message: 'User account deleted successfully' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Fetch all users for admin
app.get('/api/auth/admin/users', async (req, res) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ message: 'No token provided' });

  jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret_here', async (err, decoded) => {
    if (err) return res.status(403).json({ message: 'Failed to authenticate token' });

    if (!decoded.isAdmin) return res.status(403).json({ message: 'Access denied' });

    const users = await User.find().select('-password');
    res.json(users);
  });
});


// app.get('/api/auth/profile', async (req, res) => {
//   const authHeader = req.headers['authorization'];

//   if (!authHeader) {
//     return res.status(401).json({ message: 'No token provided' });
//   }

//   // Check if the token includes the "Bearer" prefix and extract the JWT
//   const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : authHeader;

//   jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret_here', async (err, decoded) => {
//     if (err) {
//       return res.status(403).json({ message: 'Failed to authenticate token' });
//     }

//     try {
//       // Token is valid; find and return the user profile without the password field
//       const user = await User.findById(decoded.userId).select('-password');
//       if (!user) {
//         return res.status(404).json({ message: 'User not found' });
//       }

//       res.status(200).json(user);
//     } catch (error) {
//       console.error('Error fetching user profile:', error);
//       res.status(500).json({ message: 'Server error' });
//     }
//   });
// });

app.get('/api/auth/profile', async (req, res) => {
  const authHeader = req.headers['authorization'];
  
  if (!authHeader) {
    return res.status(401).json({ message: 'No token provided' });
  }

  const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : authHeader;

  jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret_here', async (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Failed to authenticate token' });
    }

    try {
      const user = await User.findById(decoded.userId).select('-password');
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      // Ensure 'uploads/' prefix in profileImage path
      const profileImagePath = user.profileImage ? `uploads/${user.profileImage}` : null;
      res.status(200).json({ ...user.toObject(), profileImage: profileImagePath });
      
    } catch (error) {
      console.error('Error fetching user profile:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });
});



// Update User Status (Activate/Deactivate)
app.put('/api/auth/update-status/:id', async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { isActive: req.body.isActive },
      { new: true }
    );

    if (!user) return res.status(404).json({ message: 'User not found' });
    
    res.json(user);
  } catch (error) {
    console.error('Error updating user status:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Add a new expense
// app.post('/api/expenses/add/:userId', async (req, res) => {
//   const token = req.headers['authorization'];
//   if (!token) return res.status(401).json({ message: 'No token provided' });

//   jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret_here', async (err, decoded) => {
//     if (err) return res.status(403).json({ message: 'Failed to authenticate token' });

//     const { date, category, description, amount } = req.body;

//     try {
//       const expense = new Expense({
//         userId: decoded.userId, // use decoded userId
//         date,
//         category,
//         description,
//         amount
//       });

//       await expense.save();
//       res.status(201).json({ message: 'Expense added successfully', expense });
//     } catch (error) {
//       console.error("Error adding expense:", error);
//       res.status(500).json({ message: 'Failed to add expense' });
//     }
//   });
// });

app.post('/api/expenses/add', async (req, res) => {
  const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });

  jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret_here', async (err, decoded) => {
    if (err) return res.status(403).json({ message: 'Failed to authenticate token' });

    const { date, category, description, amount } = req.body;

    try {
      const expense = new Expense({
        userId: decoded.userId, // use decoded userId directly
        date,
        category,
        description,
        amount
      });

     
      await expense.save();
      res.status(201).json({ message: 'Expense added successfully', expense });
    } catch (error) {
      console.error("Error adding expense:", error);
      res.status(500).json({ message: 'Failed to add expense' });
    }
  });
});

// Expenses-list API
app.get('/monthly/:userId',  async (req, res) => {
  const { userId } = req.params;

  try {
    const expensesByMonth = await Expense.aggregate([
      { $match: { userId } }, // Filter by userId
      {
        $group: {
          _id: { month: { $month: "$date" }, year: { $year: "$date" } },
          total: { $sum: "$amount" },
          expenses: {
            $push: {
              date: "$date",
              category: "$category",
              description: "$description",
              amount: "$amount"
            }
          }
        }
      },
      { $sort: { "_id.year": -1, "_id.month": -1 } } // Sort by recent months
    ]);

    // Format response to match your mock data structure
    const formattedData = expensesByMonth.map(monthData => ({
      name: `${new Date(monthData._id.year, monthData._id.month - 1).toLocaleString('default', { month: 'long' })} ${monthData._id.year}`,
      total: monthData.total,
      expenses: monthData.expenses
    }));

    res.json(formattedData);
  } catch (error) {
    console.error('Error fetching expenses by month:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// End of Expenses-list API


// monthly expenses API
app.get('/api/expenses/monthly/:userId', async (req, res) => {
  const { userId } = req.params;
  const { month, year } = req.query; // e.g., month=3, year=2024
  
  try {
    const monthlyExpenses = await Expense.aggregate([
      { 
        $match: { 
          userId: new mongoose.Types.ObjectId(userId), 
          date: {
            $gte: new Date(`${year}-${month}-01`),
            $lt: new Date(`${year}-${parseInt(month) + 1}-01`)
          } 
        } 
      },
      { $sort: { date: 1 } }, // Sort by date
      {
        $group: {
          _id: null, // Group all expenses for the specified month
          totalAmount: { $sum: "$amount" },
          expenses: { $push: { date: "$date", category: "$category", description:"$description", amount: "$amount" } }
        }
      }
    ]);

    // Format response
    const result = monthlyExpenses.length > 0 ? monthlyExpenses[0] : { totalAmount: 0, expenses: [] };
    res.json(result);
  } catch (err) {
    console.error("Error fetching monthly expenses:", err);
    res.status(500).send('Error fetching monthly expenses');
  }
});

// End Of Monthly Expenses API

// start of monthly report

app.get('/api/expenses/report/monthly/:userId', async (req, res) => {
  const { userId } = req.params;
  const { month, year } = req.query; // e.g., month=3, year=2024
  
  try {
    const monthlyExpenses = await Expense.aggregate([
      { 
        $match: { 
          userId: new mongoose.Types.ObjectId(userId), 
          date: {
            $gte: new Date(`${year}-${month}-01`),
            $lt: new Date(`${year}-${parseInt(month) + 1}-01`)
          } 
        } 
      },
      { 
        $group: {
          _id: "$category", // Group by category for chart data
          totalAmount: { $sum: "$amount" }
        }
      }
    ]);

    // Calculate total expenses for the month
    const totalAmount = monthlyExpenses.reduce((sum, item) => sum + item.totalAmount, 0);

    // Format response for chart.js
    const response = {
      labels: monthlyExpenses.map(item => item._id), // Categories as labels
      data: monthlyExpenses.map(item => item.totalAmount), // Amounts as data points
      total: totalAmount
    };

    res.json(response);
  } catch (err) {
    console.error("Error fetching monthly report:", err);
    res.status(500).send('Error fetching monthly report');
  }
});







// Fetch Annual Expenses

app.get('/api/expenses/annual-expenses/:userId', async (req, res) => {
  const { userId } = req.params;
  const year = parseInt(req.query.year) || new Date().getFullYear();
  
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Extract token after 'Bearer'
  if (!token) return res.status(401).json({ message: 'No token provided' });

  jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret_here', async (err, decoded) => {
    if (err) return res.status(403).json({ message: 'Failed to authenticate token' });

    if (decoded.userId !== userId && !decoded.isAdmin) {
      return res.status(403).json({ message: 'Access denied' });
    }

    try {
      const startDate = new Date(`${year}-01-01T00:00:00.000Z`);
      const endDate = new Date(`${year + 1}-01-01T00:00:00.000Z`);

      const expenses = await Expense.aggregate([
        { 
          $match: { 
            userId: new mongoose.Types.ObjectId(userId),  
            date: { $gte: startDate, $lt: endDate } 
          } 
        },
        {
          $group: {
            _id: { month: { $month: "$date" } },
            totalAmount: { $sum: "$amount" },
            count: { $sum: 1 },
            transactions: { $push: { description: "$description", amount: "$amount", category: "$category", date: "$date" } }
          }
        },
        { 
          $sort: { "_id.month": 1 } 
        }
      ]);

      const formattedExpenses = expenses.map(e => ({
        month: e._id.month,
        total: e.totalAmount,
        transactions: e.count,
        details: e.transactions
      }));

      res.status(200).json({ year, expenses: formattedExpenses });
    } catch (error) {
      console.error("Error fetching annual expenses:", error);
      res.status(500).json({ message: 'Failed to fetch annual expenses' });
    }
  });
});

app.get('/api/expenses/:userId/:duration', async (req, res) => {
  const { userId, duration } = req.params;
  
  // Determine the date range based on the duration
  let startDate;
  const endDate = new Date(); // Current date

  switch (duration) {
    case 'daily':
      startDate = new Date();
      startDate.setHours(0, 0, 0, 0); // Start of the day
      break;
    case 'weekly':
      startDate = new Date();
      startDate.setDate(endDate.getDate() - 7); // Start of the last 7 days
      break;
    case 'monthly':
      startDate = new Date();
      startDate.setDate(1); // Start of the current month
      break;
    default:
      return res.status(400).json({ message: 'Invalid duration specified' });
  }

  try {
    // Fetch expenses by userId and within the specified date range
    const expenses = await Expense.find({
      userId,
      date: { $gte: startDate, $lt: endDate }
    });

    res.json(expenses);
  } catch (error) {
    console.error('Error fetching expenses by duration:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Category Endpoints

// Get all categories
app.get('/api/categories', async (req, res) => {
  try {
    const categories = await Category.find();
    res.json(categories);
  } catch (error) {
    console.error('Error fetching categories:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get a category by ID
app.get('/api/categories/:id', async (req, res) => {
  try {
    const category = await Category.findById(req.params.id);
    if (!category) return res.status(404).json({ message: 'Category not found' });
    res.json(category);
  } catch (error) {
    console.error('Error fetching category:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Add a new category
app.post('/api/categories', async (req, res) => {
  try {
    const category = new Category({ name: req.body.name });
    await category.save();
    res.status(201).json({ message: 'Category added successfully', category });
  } catch (error) {
    console.error('Error adding category:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update a category by ID
app.put('/api/categories/:id', async (req, res) => {
  try {
    const category = await Category.findByIdAndUpdate(req.params.id, { name: req.body.name }, { new: true });
    if (!category) return res.status(404).json({ message: 'Category not found' });
    res.json({ message: 'Category updated successfully', category });
  } catch (error) {
    console.error('Error updating category:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete a category by ID
app.delete('/api/categories/:id', async (req, res) => {
  try {
    const category = await Category.findByIdAndDelete(req.params.id);
    if (!category) return res.status(404).json({ message: 'Category not found' });
    res.json({ message: 'Category deleted successfully' });
  } catch (error) {
    console.error('Error deleting category:', error);
    res.status(500).json({ message: 'Server error' });
  }
});


// Get settings for a user
app.get('/api/user-settings/:userId', async (req, res) => {
  try {
    const settings = await UserSettings.findOne({ userId: req.params.userId });
    res.json(settings);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching user settings' });
  }
});

// Update settings for a user
app.put('/api/user-settings/:userId', async (req, res) => {
  try {
    const updatedSettings = await UserSettings.findOneAndUpdate(
      { userId: req.params.userId },
      req.body,
      { new: true, upsert: true }
    );
    res.json(updatedSettings);
  } catch (error) {
    res.status(500).json({ message: 'Error updating user settings' });
  }
});



// Serve uploaded images
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
