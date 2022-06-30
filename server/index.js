const express = require("express");
const app = express();
const cors = require("cors");
const PORT = process.env.PORT || 5000;
const connect = require("./lib/mongo-connect");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const jwtVerify = require("./middleware/jwtVerify");
const { ObjectId } = require("mongodb");

require("dotenv").config();

app.use(
  cors({
    origin: "http://localhost:3000",
  })
);

app.use(express.json());

//------------------- AUTH -----------------//

// register
app.post("/api/registration", async (req, res) => {
  const { name, email, password, phone } = req.body;

  if (!name || !email || !password || !phone)
    return res.status(403).json("Missing required credentials.");

  try {
    const client = await connect();
    const db = client.db();
    const UserCollection = db.collection("users");
    // Check if email exists
    const emailExist = await UserCollection.find({ email }).toArray();

    if (emailExist.length !== 0) {
      return res.status(400).send({ message: "User already exists!" });
    }

    // Encrypt password using bcrypt
    const saltRound = 10;
    const hashedPassword = await bcrypt.hash(password, saltRound);

    // Creating new user
    const newUser = await UserCollection.insertOne({
      name,
      email,
      password: hashedPassword,
      phone,
    });
    // Generate token
    const token = jwt.sign({ email }, "Some secret", {
      expiresIn: "3hr",
    });

    res.status(201).json({ token: token });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: error });
  }
});

// login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(403).json("Missing required fields");

  try {
    const client = await connect();
    const db = client.db();
    const UserCollection = db.collection("users");
    // Check if email exists
    const user = await UserCollection.findOne({ email });

    if (!user) return res.status(403).json("Invalid email/password");

    // Check password
    const passDidMatch = await bcrypt.compare(password, user.password);

    if (!passDidMatch) {
      return res.status(400).json({ message: "Invalid password/email" });
    }

    // // Generate token
    const token = jwt.sign({ email }, "Some secret", {
      expiresIn: "3hr",
    });

    res.status(200).json({ token: token });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: error });
  }
});

//----------------- BILLING -------------//

//Add bill
app.post("/api/add-billing", jwtVerify, async (req, res) => {
  const { name, amount, email, phone } = req.body;
  if (!name || !amount || !email || !phone)
    return res.status(403).json("Missing required fields");

  try {
    const client = await connect();
    const db = client.db();
    const BillCollection = db.collection("bill");

    const bill = await BillCollection.insertOne({ name, amount, email, phone });

    return res.status(201).json({ id: bill.insertedId.toString() });
  } catch (error) {
    return res.status(500).json({ message: error });
  }
});

// Get All Bill
app.get("/api/billing-list", jwtVerify, async (req, res) => {
  try {
    const client = await connect();
    const db = client.db();
    const BillCollection = db.collection("bill");

    const bill = await BillCollection.find({}).toArray();

    return res.status(200).json(bill);
  } catch (error) {
    return res.status(500).json({ message: error });
  }
});

// Update Bill
app.put("/api/update-billing/:id", async (req, res) => {
  const { name, amount, email, phone } = req.body;

  if (!req.params.id) return res.status(403).json("Missing id");

  if (!name || !amount || !email || !phone)
    return res.status(403).json("Missing required fields");

  try {
    const client = await connect();
    const db = client.db();
    const BillCollection = db.collection("bill");
    let id = req.params.id;
    id = new ObjectId(id);

    let bill = await BillCollection.findOne({ _id: id });

    if (!bill) return res.status(404).json("Bill not found");

    bill = await BillCollection.findOneAndUpdate(
      { _id: id },
      { $set: { name, amount, email, phone } },
      { returnDocument: "after" }
    );

    res.status(200).json(bill.value);
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: error });
  }
});

// Delete Single Bill
app.delete("/api/delete-billing/:id", async (req, res) => {
  if (!req.params.id) return res.status(403).json("Missing id");

  try {
    const client = await connect();
    const db = client.db();
    const BillCollection = db.collection("bill");
    let id = req.params.id;
    id = new ObjectId(id);

    let bill = await BillCollection.findOne({ _id: id });

    if (!bill) return res.status(404).json("Bill not found");

    bill = await BillCollection.deleteOne({ _id: id });

    res
      .status(200)
      .json({ success: true, message: "Bill deleted successfully" });
  } catch (error) {
    return res.status(500).json({ message: error });
  }
});

app.listen(PORT, () => {
  console.log("Server is running");
});
