const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const { MongoClient, ServerApiVersion } = require("mongodb");
const cookieParser = require("cookie-parser");

const app = express();
const port = process.env.PORT || 3001;
app.use(cookieParser());
app.use(express.json());
app.use(
  cors({
    origin: ["http://localhost:3000", "https://thread-client-three.vercel.app"],
    credentials: true,
  }),
);

// jwt token generate
const generateToken = (user) => {
  return jwt.sign(
    {
      id: user._id,
      email: user.email,
      role: user.role,
    },
    process.env.JWT_SECRET,
    { expiresIn: "1d" },
  );
};
const verifyToken = (req, res, next) => {
  const token = req.cookies?.token;

  if (!token) {
    return res.status(401).send({ message: "Unauthorized access" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).send({ message: "Invalid or expired token" });
    }

    req.user = decoded;
    next();
  });
};
app.get("/", (req, res) => {
  res.send("thread & co. is running...");
});

const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});
const db = client.db("thread");
const usersCollection = db.collection("users");
const productsCollection = db.collection("products");

app.post("/api/register", async (req, res) => {
  const user = req.body;
  if (!user) {
    return res.status(400).send({ message: "User data is required" });
  }

  const email = user.email;
  const isExisting = await usersCollection.findOne({ email });
  if (isExisting) {
    return res.status(400).send({ message: "User already exist" });
  }

  const saltRounds = 10;
  const plainPassword = user.password;
  const hashedAdminPassword = await bcrypt.hash(plainPassword, saltRounds);
  const userToDB = {
    name: user.name,
    email: user.email,
    password: hashedAdminPassword,
    photoURL: user.photoURL,
    role: "user",
    createdAt: new Date(),
  };
  const result = await usersCollection.insertOne(userToDB);
  const newUser = {
    id: result.insertedId,
    name: user.name,
    email: user.email,
    role: "user",
  };

  const token = generateToken(newUser);
  res
    .cookie("token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 24 * 60 * 60 * 1000,
    })
    .send({
      success: true,
      message: "Signup successful",
      user: newUser,
    });
});
// user login api
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.send("email & pass are required");
  }
  const user = await usersCollection.findOne({ email });
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.send("password is incorrect!");
  }
  const token = generateToken({
    id: user._id,
    email: user.email,
    role: user.role,
  });
  const userWithoutPassword = { ...user };
  delete userWithoutPassword.password;
  res
    .cookie("token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 24 * 60 * 60 * 1000,
    })
    .send({
      success: true,
      message: "login successful",
      user: userWithoutPassword,
    });
});
app.get("/api/me", verifyToken, async (req, res) => {
  try {
    const email = req.user.email;
    const query = { email: email };

    const user = await usersCollection.findOne(query, {
      projection: { password: 0 },
    });

    if (!user) {
      return res.status(404).send({ message: "User not found" });
    }

    res.send(user);
  } catch (error) {
    res.status(500).send({ message: "Internal server error" });
  }
});
// logout api
app.post("/api/logout", async (req, res) => {
  res
    .clearCookie("token", {
      httpOnly: true,
      secure: true,
      sameSite: "none",
    })
    .send({
      success: true,
      message: "Logout successful",
    });
});
app.get("/api/users", async (req, res) => {
  const result = await usersCollection.find().toArray();
  res.send(result);
});

// products api
app.get("/api/products", async (req, res) => {
  const result = await productsCollection.find().toArray();
  res.send(result);
});
app.get("/api/products/query", async (req, res) => {
  const { search, sort } = req.query;
  const cats = req.query["cats[]"];

  const query = {};
  if (cats) {
    const catsArr = Array.isArray(cats) ? cats : [cats];
    if (catsArr && catsArr.length > 0) {
      query.category = { $in: catsArr };
    }
  }

  const sortQuery = {
    price: sort === "asc" ? 1 : -1,
  };

  if (search) {
    query.$or = [{ name: { $regex: search, $options: "i" } }];
  }
  const result = await productsCollection.find(query).sort(sortQuery).toArray();
  res.send(result);
});
async function connectDB() {
  try {
    await client.connect();
    console.log("Database connected!");
  } catch (err) {
    console.error(err);
  }
}
connectDB();

module.exports = app;

if (process.env.NODE_ENV !== "production") {
  app.listen(port, () => console.log("Server running on 3001"));
}
