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
        const genresCollection = db.collection("genres");
        const booksCollection = db.collection("books");

        // more middleware
        const verifyAdmin = async (req, res, next) => {
            const email = req.token_email;
            const user = await usersCollection.findOne({ email });
            if (!user || user.role !== "admin") {
                return res.status(403).send({ message: "Forbidden Access!" });
            }
            next();
        };

        // users auth and role related api's

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
                name: user.name,
                email: user.email,
                photo: user.photo || "",
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

        // get all users
        app.get("/users", verifyFireBaseToken, verifyAdmin, async (req, res) => {
            const cursor = usersCollection.find();
            const result = await cursor.toArray();
            res.send(result);
        });

        // change user role
        app.patch("/users/:id/role", verifyFireBaseToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const { role } = req.body;
            const query = { _id: new ObjectId(id) }
            const update = {
                $set: { role }
            };

            const result = await usersCollection.updateOne(query, update);
            res.send(result);
        });

        // admin CRUD related api's

        // get list of genres
        app.get("/genres", verifyFireBaseToken, async (req, res) => {
            const cursor = genresCollection.find().sort({ name: 1 });
            const result = await cursor.toArray();
            res.send(result);
        });

        // create a genre
        app.post("/genres", verifyFireBaseToken, verifyAdmin, async (req, res) => {
            const { name } = req.body;

            if (!name || !name.trim()) {
                return res.status(400).send({ message: "Genre name is required" });
            }

            const exists = await genresCollection.findOne({
                name: { $regex: name, $options: "i" },
            });

            if (exists) {
                return res.status(409).send({ message: "Genre already exists" });
            }

            const newGenre = {
                name: name.trim(),
                createdAt: new Date()
            };

            const result = await genresCollection.insertOne(newGenre);
            res.send(result);
        });

        // update a genre
        app.patch("/genres/:id", verifyFireBaseToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const { name } = req.body;
            const query = { _id: new ObjectId(id) };

            if (!name || !name.trim()) {
                return res.status(400).send({ message: "Genre name is required" });
            }

            const update = {
                $set: {
                    name: name.trim()
                }
            }

            const result = await genresCollection.updateOne(query, update);
            res.send(result);
        });

        // delete a genre (block if books exist)
        app.delete("/genres/:id", verifyFireBaseToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };

            const hasBook = await booksCollection.findOne({ genreId: id });

            if (hasBook) {
                return res.status(409).send({
                    message: "Cannot delete: this genre is used by one or more books",
                });
            }

            const result = await genresCollection.deleteOne(query);
            res.send(result);
        });

        // books related api's

        // browse books with search, filter, pagination and sort
        app.get("/books", verifyFireBaseToken, async (req, res) => {
            const {
                page = 1,
                limit = 10,
                search = "",
                genre = "",
                minRating,
                maxRating,
                sort = "newest",
            } = req.query;

            const pg = Math.max(parseInt(page), 1);
            const lm = Math.min(Math.max(parseInt(limit), 1), 50);

            const query = {};

            // search by title or author
            if (search) {
                query.$or = [
                    { title: { $regex: search, $options: "i" } },
                    { author: { $regex: search, $options: "i" } },
                ];
            }

            // multi genre filter: genre=id1,id2
            if (genre) {
                const ids = genre.split(",").map((x) => x.trim()).filter(Boolean);
                
                if (ids.length > 0) {
                    query.genreId = { $in: ids };
                }
            }

            // rating range
            if (minRating || maxRating) {
                query.avgRating = {};
                if (minRating) {
                    query.avgRating.$gte = parseFloat(minRating);
                }
                if (maxRating) {
                    query.avgRating.$lte = parseFloat(maxRating);
                }
            }

            let sortQuery = {};

            if (sort === "rating") {
                sortQuery = { avgRating: -1 };
            } else if (sort === "shelved") {
                sortQuery = { totalShelved: -1 };
            } else {
                sortQuery = { createdAt: -1 }; // newest
            }

            const total = await booksCollection.countDocuments(query);

            const books = await booksCollection
                .find(query)
                .sort(sortQuery)
                .skip((pg - 1) * lm)
                .limit(lm)
                .toArray();

            res.send({
                total,
                page: pg,
                limit: lm,
                totalPages: Math.ceil(total / lm),
                result: books,
            });
        });

        // get single book details
        app.get("/books/:id", verifyFireBaseToken, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };

            try {
                const book = await booksCollection.findOne(query);

                if (!book) {
                    return res.status(404).send({ message: "Book not found" });
                }

                return res.send(book);
            } catch {
                return res.status(400).send({ message: "Invalid book id" });
            }
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
