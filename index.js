const express = require("express");
const SSLCommerzPayment = require("sslcommerz-lts");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const cookieParser = require("cookie-parser");

const app = express();
app.set("trust proxy", 1);
const port = process.env.PORT || 3001;
app.use(cookieParser());
app.use(express.json());

app.use(
  cors({
    origin: ["http://localhost:3000", "https://thread-client-three.vercel.app"],
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  }),
);
const store_id = process.env.PAYMENT_GATEWAY_STORE_ID;
const store_passwd = process.env.PAYMENT_GATEWAY_SECRET;
const is_live = false; //true for live, false for sandbox

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
const verifyAdmin = (req, res, next) => {
  if (req.user.role !== "admin") {
    return res.status(403).send({ message: "Admin access only" });
  }
  next();
};

app.get("/", (req, res) => {
  res.send("thread & co. is running...");
});
const isProd = process.env.NODE_ENV === "production";
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});
const db = client.db("thread");
async function connectDB() {
  try {
    await client.connect();
    console.log("Database connected!");
  } catch (err) {
    console.error(err);
  }
}
connectDB();

const usersCollection = db.collection("users");
const productsCollection = db.collection("products");
const cartCollection = db.collection("cart");
const orderCollection = db.collection("orders");

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
      path: "/",
      maxAge: 24 * 60 * 60 * 1000,
    })
    .send({
      success: true,
      message: "Signup successful",
      user: newUser,
      token,
    });
});
// user login api
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.send("email & pass are required");
  }

  const user = await usersCollection.findOne({ email });
  if (!user) {
    return res.status(404).send({ message: "User not found" });
  }
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
      partitioned: true,
      sameSite: "none",
      path: "/",
      maxAge: 24 * 60 * 60 * 1000,
    })
    .send({
      success: true,
      message: "login successful",
      user: userWithoutPassword,
      token,
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
app.get("/api/users", verifyToken, verifyAdmin, async (req, res) => {
  const page = Number(req.query.page) || 1;
  const limit = Number(req.query.limit) || 10;
  const skip = (page - 1) * limit;
  const totalProduct = await productsCollection.countDocuments();
  const totalPage = Math.ceil(totalProduct / limit);
  const result = await usersCollection.find().skip(skip).limit(limit).toArray();
  res.json({
    success: true,
    totalPage,
    currentPage: page,
    totalProduct,
    result,
  });
});
app.get("/api/users/admin", verifyToken, verifyAdmin, async (req, res) => {
  const result = await usersCollection.countDocuments();
  res.send(result);
});

// products api
app.post("/api/product", verifyToken, async (req, res) => {
  const product = req.body;
  if (!product) {
    return res.send("Add a product");
  }
  const result = await productsCollection.insertOne(product);
  res.send(result);
});
app.get("/api/products/admin", verifyToken, verifyAdmin, async (req, res) => {
  const data = await productsCollection.find().toArray();
  const totalReviews = data.reduce((total, review) => {
    return total + review.reviews.length;
  }, 0);
  res.send(totalReviews);
});
app.get("/api/products", async (req, res) => {
  const result = await productsCollection.find().limit(8).toArray();
  res.send(result);
});
app.get("/api/products/query", async (req, res) => {
  const { search, sort } = req.query;
  const page = Number(req.query.page) || 1;
  const limit = Number(req.query.limit) || 10;
  const skip = (page - 1) * limit;
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
  const result = await productsCollection
    .find(query)
    .sort(sortQuery)
    .skip(skip)
    .limit(limit)
    .toArray();
  const totalProduct = await productsCollection.countDocuments();
  const totalPage = Math.ceil(totalProduct / limit);
  // res.send(result);
  res.json({
    success: true,
    totalPage,
    currentPage: page,
    totalProduct,
    result,
  });
});
app.get("/api/product/:id", async (req, res) => {
  const { id } = req.params;
  const query = { _id: new ObjectId(id) };
  const result = await productsCollection.findOne(query);
  res.send(result);
});
app.get("/api/product", async (req, res) => {
  const cats = req.query.category;
  const query = {};
  if (cats) {
    query.category = cats;
  }
  const result = await productsCollection.find(query).toArray();
  res.send(result);
});
// product delete api
app.delete("/api/product/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  const query = { _id: new ObjectId(id) };
  const result = await productsCollection.deleteOne(query);
  res.send(result);
});
// Edit/update product api
app.patch("/api/products/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  const updateData = req.body;

  const result = await productsCollection.updateOne(
    { _id: new ObjectId(id) },
    {
      $set: updateData,
    },
  );

  res.send(result);
});

// Cart related api
app.post("/api/product/cart", async (req, res) => {
  const productData = req.body;
  const { email, productId, size } = productData;
  const query = { email, productId, size };
  const isExist = await cartCollection.findOne(query);
  if (isExist) {
    const updatedDoc = {
      $inc: {
        quantity: 1,
      },
    };
    const result = await cartCollection.updateOne(query, updatedDoc);
    return res.send(result);
  } else {
    const result = await cartCollection.insertOne(productData);
    res.send(result);
  }
});
app.get("/api/cart/admin", async (req, res) => {
  const result = await cartCollection.countDocuments();
  res.send(result);
});
app.get("/api/cart/:email", async (req, res) => {
  const { email } = req.params;
  const query = {};
  if (email) {
    query.email = email;
  }
  const result = await cartCollection.find(query).toArray();
  res.send(result);
});
app.get("/api/my-cart", async (req, res) => {
  const email = req?.query?.email;
  if (email) {
    const result = await cartCollection
      .aggregate([
        { $match: { email: email } },
        {
          $addFields: {
            productId: { $toObjectId: "$productId" },
          },
        },
        {
          $lookup: {
            from: "products",
            localField: "productId",
            foreignField: "_id",
            as: "productData",
          },
        },
        { $unwind: "$productData" },
      ])
      .toArray();
    return res.send(result);
  }
});
app.delete("/api/cart/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  const query = { _id: new ObjectId(id) };
  const result = await cartCollection.deleteOne(query);
  res.send(result);
});

// admin dashboard chart related apis
app.get(
  "/api/users-stats/admin",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    const monthlyData = await usersCollection
      .aggregate([
        {
          $group: {
            _id: {
              monthName: {
                $dateToString: { format: "%b", date: "$createdAt" },
              },
              year: { $year: "$createdAt" },
              monthNumber: { $month: "$createdAt" },
            },
            totalUsers: { $sum: 1 },
          },
        },
        {
          $sort: { "_id.year": 1, "_id.monthNumber": 1 },
        },
        {
          $project: {
            _id: 0,
            month: "$_id.monthName",
            year: "$_id.year",
            totalUsers: 1,
          },
        },
      ])
      .toArray();
    res.send(monthlyData);
  },
);

// payment gateway related api

app.post("/api/order", async (req, res) => {
  const order = req.body;
  const email = order?.email?.trim();
  const cartData = await cartCollection
    .aggregate([
      { $match: { email: email } },
      {
        $addFields: {
          productId: { $toObjectId: "$productId" },
        },
      },
      {
        $lookup: {
          from: "products",
          localField: "productId",
          foreignField: "_id",
          as: "productData",
        },
      },
      { $unwind: "$productData" },
    ])
    .toArray();
  const cartOrderData = await cartCollection.find({ email: email }).toArray();
  const totalPrice = cartData.reduce((total, item) => {
    return total + item.productData.price * item.quantity;
  }, 0);
  const fullName = order.firstName + " " + order.lastName;

  const tran_id = new ObjectId().toString();
  const data = {
    total_amount: totalPrice + order.shippingFee,
    currency: order.currency,
    tran_id: tran_id, // use unique tran_id for each api call
    success_url: `http://localhost:3001/api/payment/success/${tran_id}`,
    fail_url: "http://localhost:3000/fail",
    cancel_url: "http://localhost:3000/cancel",
    ipn_url: "http://localhost:3000/ipn",
    shipping_method: "Courier",
    product_name: "Computer.",
    product_category: "Electronic",
    product_profile: "general",
    cus_name: fullName,
    cus_email: email,
    cus_add1: order?.city,
    cus_add2: order?.city,
    cus_city: order?.city,
    cus_state: order?.state,
    cus_postcode: order?.zip,
    cus_country: order?.country,
    cus_phone: order?.phone,
    cus_fax: "01711111111",
    ship_name: fullName,
    ship_add1: "Dhaka",
    ship_add2: "Dhaka",
    ship_city: order?.city,
    ship_state: order?.state,
    ship_postcode: order?.zip,
    ship_country: order?.country,
  };
  const sslcz = new SSLCommerzPayment(store_id, store_passwd, is_live);
  sslcz.init(data).then((apiResponse) => {
    let GatewayPageURL = apiResponse.GatewayPageURL;
    res.send({ url: GatewayPageURL });
  });

  const finalOrder = {
    ...cartOrderData,
    transactionId: tran_id,
    totalPrice,
    paidStatus: false,
  };
  const result = await orderCollection.insertOne(finalOrder);

  app.post("/api/payment/success/:tranId", async (req, res) => {
    const result = await orderCollection.updateOne(
      {
        transactionId: req.params.tranId,
      },
      {
        $set: {
          paidStatus: true,
        },
      },
    );
    if (result.modifiedCount) {
      res.redirect(`http://localhost:3000/paymentSuccess/${tran_id}`);
    }
  });
});

module.exports = app;

if (process.env.NODE_ENV !== "production") {
  app.listen(port, () => console.log("Server running on 3001"));
}
