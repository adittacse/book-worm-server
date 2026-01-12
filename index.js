const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion } = require("mongodb");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

// middleware
app.use(cors());
app.use(express.json());

// helpers
const isStrongPassword = (pw) => {
    // upper, lower, number
    if (!pw || pw.length < 8) {
        return false;
    }
    const hasUpper = /[A-Z]/.test(pw);
    const hasLower = /[a-z]/.test(pw);
    const hasNumber = /[0-9]/.test(pw);
    return hasUpper && hasLower && hasNumber;
};

const signToken = (payload) => {
    return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "7d" });
};

// auth middleware
const verifyToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).send({ message: "Unauthorized Access" });
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
        return res.status(401).send({ message: "Unauthorized Access" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; // { email, role, userId }
        next();
    } catch (err) {
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
            const email = req.user?.email;
            const user = await usersCollection.findOne({ email });
            if (!user || user.role !== "admin") {
                return res.status(403).send({ message: "Forbidden Access!" });
            }
            next();
        };

        /* =========================================================
            AUTH: Registration & Login (Requirement MUST)
        ========================================================= */

        // Registration (manual)
        app.post("/auth/register", async (req, res) => {
            try {
                const { name, email, photo, password } = req.body;

                // required fields check
                if (!name || !email || !photo || !password) {
                    return res.status(400).send({
                        message: "Missing fields: name, email, photo, password",
                    });
                }

                // password strength check
                if (!isStrongPassword(password)) {
                    return res.status(400).send({
                        message: "Weak password. Use 8+ chars with uppercase, lowercase & number.",
                    });
                }

                // duplicate email check
                const exists = await usersCollection.findOne({ email });
                if (exists) {
                    return res.status(409).send({ message: "Email already exists" });
                }

                const passwordHash = await bcrypt.hash(password, 10);

                const newUser = {
                    name: name.trim(),
                    email: email.trim().toLowerCase(),
                    photo: photo.trim(),
                    role: "user",
                    provider: "manual",
                    passwordHash,
                    createdAt: new Date(),
                };

                const result = await usersCollection.insertOne(newUser);

                // optional: auto-login token
                const token = signToken({
                    userId: result.insertedId.toString(),
                    email: newUser.email,
                    role: newUser.role,
                });

                res.send({
                    ok: true,
                    message: "Registered successfully",
                    token,
                    user: {
                        name: newUser.name,
                        email: newUser.email,
                        photo: newUser.photo,
                        role: newUser.role,
                    },
                });
            } catch (err) {
                res.status(500).send({ message: "Server error in registration" });
            }
        });

        // Login (manual)
        app.post("/auth/login", async (req, res) => {
            try {
                const { email, password } = req.body;

                if (!email || !password) {
                    return res.status(400).send({ message: "Email and password are required" });
                }

                const user = await usersCollection.findOne({
                    email: email.trim().toLowerCase(),
                });

                // user must exist & must be manual for credential login
                if (!user || user.provider !== "manual") {
                    return res.status(401).send({ message: "Invalid credentials" });
                }

                const match = await bcrypt.compare(password, user.passwordHash);
                if (!match) {
                    return res.status(401).send({ message: "Invalid credentials" });
                }

                const token = signToken({
                    userId: user._id.toString(),
                    email: user.email,
                    role: user.role || "user",
                });

                res.send({
                    ok: true,
                    token,
                    user: {
                        name: user.name,
                        email: user.email,
                        photo: user.photo,
                        role: user.role || "user",
                    },
                });
            } catch (err) {
                res.status(500).send({ message: "Server error in login" });
            }
        });

        // Logged-in: get my role (self)
        app.get("/users/me/role", verifyToken, async (req, res) => {
            const email = req.user.email;
            const user = await usersCollection.findOne({ email });
            res.send({ role: user?.role || "user" });
        });

        /* =========================================================
            USERS (Admin) - keep your earlier features
        ========================================================= */
        app.get("/users", verifyToken, verifyAdmin, async (req, res) => {
            const result = await usersCollection.find().toArray();
            res.send(result);
        });

        app.patch("/users/:id/role", verifyToken, verifyAdmin, async (req, res) => {
                const id = req.params.id;
                const { role } = req.body;
                const query = { _id: new ObjectId(id) };

                if (!role || !["admin", "user"].includes(role)) {
                    return res.status(400).send({ message: "Invalid role" });
                }

                const update = {
                    $set: { role }
                };

                const result = await usersCollection.updateOne(query, update);
                res.send(result);
            },
        );

        /* =========================================================
            GENRES (Protected) - same logic, just middleware changed
        ========================================================= */
        app.get("/genres", verifyToken, async (req, res) => {
            const cursor = genresCollection.find().sort({ name: 1 });
            const result = await cursor.toArray();
            res.send(result);
        });

        app.post("/genres", verifyToken, verifyAdmin, async (req, res) => {
            const { name } = req.body;

            if (!name || !name.trim()) {
                return res.status(400).send({ message: "Genre name is required" });
            }

            const query = { name: { $regex: name.trim(), $options: "i" } };

            const exists = await genresCollection.findOne(query);
            if (exists) {
                return res.status(409).send({ message: "Genre already exists" });
            }

            const newGenre = {
                name: name.trim(),
                createdAt: new Date(),
            };

            const result = await genresCollection.insertOne(newGenre);
            res.send(result);
        });

        app.patch("/genres/:id", verifyToken, verifyAdmin, async (req, res) => {
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
            };

            const result = await genresCollection.updateOne(query, update);
            res.send(result);
        });

        app.delete("/genres/:id", verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };

            const hasBook = await booksCollection.findOne({ genreId: id });
            
            if (hasBook) {
                return res.status(409).send({
                    message: "Cannot delete. This genre is used by one or more books",
                });
            }

            const result = await genresCollection.deleteOne(query);
            res.send(result);
        });

        /* =========================================================
            BOOKS (Protected) - same logic, just middleware changed
        ========================================================= */
        app.get("/books", verifyToken, async (req, res) => {
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

            if (search) {
                query.$or = [
                    { title: { $regex: search, $options: "i" } },
                    { author: { $regex: search, $options: "i" } },
                ];
            }

            if (genre) {
                const ids = genre.split(",").map((x) => x.trim()).filter(Boolean);
                if (ids.length > 0) {
                    query.genreId = { $in: ids };
                }
            }

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
                sortQuery = { createdAt: -1 };
            }

            const total = await booksCollection.countDocuments(query);

            const booksCursor = booksCollection.find(query).sort(sortQuery).skip((pg - 1) * lm).limit(lm);
            const books = await booksCursor.toArray();

            res.send({
                total,
                page: pg,
                limit: lm,
                totalPages: Math.ceil(total / lm),
                result: books,
            });
        });

        app.get("/books/:id", verifyToken, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };

            try {
                const book = await booksCollection.findOne(query);
                
                if (!book) {
                    return res.status(404).send({ message: "Book not found" });
                }

                res.send(book);
            } catch {
                res.status(400).send({ message: "Invalid book id" });
            }
        });

        app.post("/books", verifyToken, verifyAdmin, async (req, res) => {
            const {
                title,
                author,
                genreId,
                description,
                coverImage,
                totalPages,
            } = req.body;
            const query = { _id: new ObjectId(genreId) };

            if (!title || !author || !genreId || !description || !coverImage) {
                return res.status(400).send({ message: "Missing required fields" });
            }

            const genreExists = await genresCollection.findOne(query);

            if (!genreExists) {
                return res.status(400).send({ message: "Invalid genreId" });
            }

            const newBook = {
                title: title.trim(),
                author: author.trim(),
                genreId,
                description: description.trim(),
                coverImage: coverImage.trim(),
                totalPages: totalPages ? parseInt(totalPages) : 0,
                avgRating: 0,
                totalShelved: 0,
                createdAt: new Date(),
            };

            const result = await booksCollection.insertOne(newBook);
            res.send(result);
        });

        app.patch("/books/:id", verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const updated = req.body || {};
            const updateDoc = { $set: {} };

            if (updated.title) {
                updateDoc.$set.title = updated.title.trim();
            }
            if (updated.author) {
                updateDoc.$set.author = updated.author.trim();
            }
            if (updated.description) {
                updateDoc.$set.description = updated.description.trim();
            }
            if (updated.coverImage) {
                updateDoc.$set.coverImage = updated.coverImage.trim();
            }
            if (updated.totalPages !== undefined) {
                updateDoc.$set.totalPages = parseInt(updated.totalPages) || 0;
            }

            if (updated.genreId) {
                const genreExists = await genresCollection.findOne({ _id: new ObjectId(updated.genreId) });
                
                if (!genreExists) {
                    return res.status(400).send({ message: "Invalid genreId" });
                }

                updateDoc.$set.genreId = updated.genreId;
            }

            if (Object.keys(updateDoc.$set).length === 0) {
                return res.send({ message: "Nothing to update" });
            }

            try {
                const result = await booksCollection.updateOne(query, updateDoc);
                res.send(result);
            } catch {
                res.status(400).send({ message: "Invalid book id" });
            }
        });

        app.delete("/books/:id", verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            
            try {
                const result = await booksCollection.deleteOne(query);
                res.send(result);
            } catch {
                res.status(400).send({ message: "Invalid book id" });
            }
        });

        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 });
        console.log(
            "Pinged your deployment. You successfully connected to MongoDB!",
        );
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
    console.log(
        `Book Worm listening on ${process.env.PROTOCOL}://${process.env.HOST}:${process.env.PORT}`,
    );
});
