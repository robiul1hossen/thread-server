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

const uri = process.env.MONGODB_URI;

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
console.log(process.env.SITE_DOMAIN);
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
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});
async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();

    const db = client.db("thread");
    const usersCollection = db.collection("users");

    app.post("/register", async (req, res) => {
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
          secure: process.env.NODE_ENV === "production",
          sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
          maxAge: 24 * 60 * 60 * 1000,
        })
        .send({
          success: true,
          message: "Signup successful",
          user: newUser,
        });
    });
    // user login api
    app.post("/login", async (req, res) => {
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
      res
        .cookie("token", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
          maxAge: 24 * 60 * 60 * 1000,
        })
        .send({
          success: true,
          message: "login successful",
          user,
        });
    });
    app.get("/me", verifyToken, async (req, res) => {
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
    app.post("/logout", async (req, res) => {
      res
        .clearCookie("token", {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
        })
        .send({
          success: true,
          message: "Logout successful",
        });
    });
    app.get("/users", async (req, res) => {
      const result = await usersCollection.find().toArray();
      res.send(result);
    });
    // Send a ping to confirm a successful connection
    // await client.db("admin").command({ ping: 1 });
    // console.log(
    //   "Pinged your deployment. You successfully connected to MongoDB!",
    // );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.listen(port, () => {
  console.log(`port is listening on ${port}`);
});
