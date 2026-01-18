const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
var jwt = require("jsonwebtoken");
require("dotenv").config();
const { MongoClient, ServerApiVersion } = require("mongodb");

const app = express();
const port = process.env.PORT || 3001;
app.use(express.json());
app.use(
  cors({
    origin: "http://localhost:3000", // Apnar Next.js app er URL
    credentials: true, // Eti must! Cookie transaction er jonno dorkar
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
          sameSite: "strict",
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
      const isPasswordValid = bcrypt.compare(user.password, password);
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
          sameSite: "strict",
          maxAge: 24 * 60 * 60 * 1000,
        })
        .send({
          success: true,
          message: "login successful",
          user,
        });
    });
    // logout api
    app.post("/logout", async (req, res) => {
      res
        .clearCookie("token", {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "strict",
        })
        .send({
          success: true,
          message: "Logout successful",
        });
    });
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!",
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.listen(port, () => {
  console.log(`port is listening on ${port}`);
});
