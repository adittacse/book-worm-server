const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion } = require("mongodb");
const dotenv = require("dotenv");
dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

// middleware
app.use(cors());
app.use(express.json());

const verifyFireBaseToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).send({ message: "Unauthorized Access" });
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
        return res.status(401).send({ message: "Unauthorized Access" });
    }

    try {
        const decoded = await admin.auth().verifyIdToken(token);
        req.token_email = decoded.email;
        next();
    } catch {
        return res.status(401).send({ message: "Unauthorized Access" });
    }
};

const uri = `mongodb+srv://${process.env.DB_USERNAME}:${process.env.DB_PASSWORD}@cluster0.gkaujxr.mongodb.net/?appName=Cluster0`;

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
        const db = client.db("bookwormDB");
        const usersCollection = db.collection("users");

        // more middleware
        const verifyAdmin = async (req, res, next) => {
            const email = req.token_email;
            const user = await usersCollection.findOne({ email });
            if (!user || user.role !== "admin") {
                return res.status(403).send({ message: "Forbidden Access!" });
            }
            next();
        };

        // get user role
        app.get("/users/:email/role", verifyFireBaseToken, async (req, res) => {
            const email = req.params.email;

            if (email !== req.token_email) {
                return res.status(403).send({ role: "user" });
            }

            const user = await usersCollection.findOne({ email });
            res.send({ role: user?.role || "user" });
        });

        // user registration
        app.post("/users", async (req, res) => {
            const user = req.body;

            const exists = await usersCollection.findOne({ email: user.email });
            if (exists) {
                return res.send({ message: "User already exists" });
            }

            const newUser = {
                ...user,
                role: "user",
                createdAt: new Date(),
            };

            const result = await usersCollection.insertOne(newUser);
            res.send(result);
        });

        // is admin check
        app.get("/users/admin/:email", verifyFireBaseToken, async (req, res) => {
            const email = req.params.email;

            if (email !== req.token_email) {
                return res.send({ admin: false });
            }

            const user = await usersCollection.findOne({ email });
            res.send({ admin: user?.role === "admin" });
        });

        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        await client.close();
    }
}
run().catch(console.dir);

app.get("/", (req, res) => {
    res.send("Book Worm server side is running!");
});

app.listen(port, () => {
    console.log(`Book Worm listening on ${process.env.PROTOCOL}://${process.env.HOST}:${process.env.PORT}`);
});
