const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
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
    if (!pw || pw.length < 6) {
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
        const libraryCollection = db.collection("libraries");
        const reviewsCollection = db.collection("reviews");
        const tutorialsCollection = db.collection("tutorials");

        // more middleware
        const verifyAdmin = async (req, res, next) => {
            const email = req.user?.email;
            const user = await usersCollection.findOne({ email });
            if (!user || user.role !== "admin") {
                return res.status(403).send({ message: "Forbidden Access!" });
            }
            next();
        };

        const recomputeBookAvgRating = async (bookId) => {
            const cursor = reviewsCollection.find({ bookId, status: "approved" }).project({ rating: 1 });
            const query = { _id: new ObjectId(bookId) };
            const approved = await cursor.toArray();

            const options = {
                $set: { avgRating: 0 }
            }

            if (approved.length === 0) {
                await booksCollection.updateOne(query, options);
                return 0;
            }

            const sum = approved.reduce((acc, r) => acc + (parseFloat(r.rating) || 0), 0);
            const avg = sum / approved.length;

            // keep 1 decimal
            const rounded = Math.round(avg * 10) / 10;

            const updateOptions = {
                $set: { avgRating: rounded }
            };

            await booksCollection.updateOne(query, updateOptions);
            return rounded;
        };

        const isYouTubeUrl = (url) => {
            if (!url) {
                return false;
            }

            try {
                const u = new URL(url);
                const host = u.hostname.replace("www.", "");
                return host === "youtube.com" || host === "youtu.be";
            } catch {
                return false;
            }
        };
        
        const getYouTubeVideoId = (url) => {
            try {
                const u = new URL(url);
                const host = u.hostname.replace("www.", "");
                if (host === "youtu.be") {
                    return u.pathname.replace("/", "");
                }
                // youtube.com/watch?v=ID
                if (u.searchParams.get("v")) {
                    return u.searchParams.get("v");
                }
                // youtube.com/embed/ID
                if (u.pathname.includes("/embed/")) {
                    return u.pathname.split("/embed/")[1];
                }
                return "";
            } catch {
                return "";
            }
        };

        /* =========================================================
            AUTH: Registration & Login (Requirement MUST)
        ========================================================= */

        // Registration (manual)
        app.post("/auth/register", async (req, res) => {
            try {
                const { name, email, photo, password } = req.body;

                if (!name || !email || !photo || !password) {
                    return res.status(400).send({
                        message: "Missing fields: name, email, photo, password",
                    });
                }

                const normalizedEmail = email.trim().toLowerCase();

                if (!isStrongPassword(password)) {
                    return res.status(400).send({
                        message: "Weak password. Use 6+ chars with uppercase, lowercase & number.",
                    });
                }
                
                const exists = await usersCollection.findOne({ email: normalizedEmail });
                if (exists) {
                    return res.status(409).send({ message: "Email already exists" });
                }

                const passwordHash = await bcrypt.hash(password, 10);

                const newUser = {
                    name: name.trim(),
                    email: normalizedEmail,
                    photo: photo.trim(),
                    role: "user",
                    provider: "manual",
                    passwordHash,
                    createdAt: new Date(),
                };

                const result = await usersCollection.insertOne(newUser);

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
                res.status(500).send({ message: err?.message || "Server error in registration" });
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

        app.post("/auth/oauth-sync", async (req, res) => {
            const apiKey = req.headers["x-api-key"];

            if (!process.env.OAUTH_SYNC_KEY || apiKey !== process.env.OAUTH_SYNC_KEY) {
                return res.status(401).send({ message: "Unauthorized" });
            }

            const { name, email, photo, provider, providerId } = req.body;

            if (!email) {
                return res.status(400).send({ message: "email required" });
            }

            const exists = await usersCollection.findOne({ email: email.toLowerCase() });

            if (!exists) {
                await usersCollection.insertOne({
                name: name || "",
                email: email.toLowerCase(),
                photo: photo || "",
                role: "user",
                provider: provider || "oauth",
                providerId: providerId || "",
                createdAt: new Date(),
                });
            }

            const user = await usersCollection.findOne({ email: email.toLowerCase() });

            const token = jwt.sign(
                { userId: user._id.toString(), email: user.email, role: user.role || "user" },
                process.env.JWT_SECRET,
                { expiresIn: "7d" }
            );

            res.send({
                ok: true,
                token,
                user: {
                    name: user.name,
                    email: user.email,
                    photo: user.photo,
                    role: user.role || "user"
                },
            });
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

        /* =========================================================
            LIBRARY (Shelves + Progress)
        ========================================================= */

        // GET my library (all shelves)
        app.get("/library/me", verifyToken, async (req, res) => {
            const email = req.user.email;

            const items = await libraryCollection
                .find({ userEmail: email })
                .sort({ updatedAt: -1 })
                .toArray();

            // book details join (simple way)
            const bookIds = items
                .map((i) => i.bookId)
                .filter(Boolean)
                .map((id) => new ObjectId(id));

            const books = await booksCollection
                .find({ _id: { $in: bookIds } })
                .toArray();

            // map: bookId -> book
            const bookMap = {};
            for (const b of books) {
                bookMap[b._id.toString()] = b;
            }

            // attach book info
            const result = items.map((i) => ({ ...i, book: bookMap[i.bookId] || null }));
            res.send(result);
        });

        // add / move book to shelf
        // body: { bookId, shelf }   shelf: want|reading|read
        app.post("/library", verifyToken, async (req, res) => {
            const email = req.user.email;
            const { bookId, shelf } = req.body;
            const query = { _id: new ObjectId(bookId) };

            if (!bookId || !shelf) {
                return res.status(400).send({ message: "bookId and shelf are required" });
            }

            if (!["want", "reading", "read"].includes(shelf)) {
                return res.status(400).send({ message: "Invalid shelf" });
            }

            // validate book exists
            let book;
            try {
                book = await booksCollection.findOne(query);
            } catch {
                return res.status(400).send({ message: "Invalid bookId" });
            }

            if (!book) {
                return res.status(404).send({ message: "Book not found" });
            }

            const userBookQuery = {
                userEmail: email,
                bookId: bookId
            };

            const existing = await libraryCollection.findOne(userBookQuery);

            // if new entry
            if (!existing) {
                const doc = {
                    userEmail: email,
                    bookId: bookId,
                    shelf,
                    progressType: "pages",
                    pagesRead: 0,
                    percent: 0,
                    createdAt: new Date(),
                    updatedAt: new Date(),
                };

                const result = await libraryCollection.insertOne(doc);

                // update book totalShelved
                await booksCollection.updateOne(query,{ $inc: { totalShelved: 1 } });

                return res.send({ ok: true, inserted: true, result });
            }

            // move shelf
            const update = {
                $set: {
                    shelf,
                    updatedAt: new Date()
                }
            };

            // if moved to read => set finishedAt
            if (shelf === "read") {
                update.$set.finishedAt = new Date();
            }

            // if moved to want => reset progress
            if (shelf === "want") {
                update.$set.pagesRead = 0;
                update.$set.percent = 0;
                update.$set.progressType = "pages";
                update.$set.finishedAt = null;
                }

            // if moved to want/read => reset progress
            if (shelf !== "reading") {
                update.$set.pagesRead = 0;
                update.$set.percent = 0;
                update.$set.progressType = "pages";
            }

            const result = await libraryCollection.updateOne(userBookQuery, update);
            res.send({ ok: true, inserted: false, result });
        });

        // UPDATE progress (only when shelf = reading)
        // body: { progressType?, pagesRead?, percent? }
        app.patch("/library/:id/progress", verifyToken, async (req, res) => {
            const email = req.user.email;
            const id = req.params.id;

            let item;
            try {
                item = await libraryCollection.findOne({
                    _id: new ObjectId(id),
                    userEmail: email,
                });
            } catch {
                return res.status(400).send({ message: "Invalid libraryId" });
            }

            if (!item) {
                return res.status(404).send({ message: "Library item not found" });
            }

            if (item.shelf !== "reading") {
                return res.status(400).send({ message: "Progress can be updated only in 'Currently Reading' shelf" });
            }

            // get book total pages
            const book = await booksCollection.findOne({ _id: new ObjectId(item.bookId) });
            const totalPages = Number(book?.totalPages || 0);

            const { progressType = "pages", pagesRead, percent } = req.body;

            if (!["pages", "percent"].includes(progressType)) {
                return res.status(400).send({ message: "Invalid progressType" });
            }

            const updateDoc = { $set: { updatedAt: new Date(), progressType } };

            if (progressType === "pages") {
                const p = parseInt(pagesRead);
                if (isNaN(p) || p < 0) {
                    return res.status(400).send({ message: "Invalid pagesRead" });
                }

                updateDoc.$set.pagesRead = p;

                // auto calculate percent when totalPages exists
                if (totalPages > 0) {
                    const pr = Math.min(Math.max((p / totalPages) * 100, 0), 100);
                    updateDoc.$set.percent = Math.round(pr); // rounded int (0-100)
                } else {
                    updateDoc.$set.percent = 0;
                }
            } else {
                const pr = parseFloat(percent);
                if (isNaN(pr) || pr < 0 || pr > 100) {
                    return res.status(400).send({ message: "Invalid percent (0-100)" });
                }

                updateDoc.$set.percent = pr;

                // auto calculate pagesRead when totalPages exists
                if (totalPages > 0) {
                const p = Math.round((pr / 100) * totalPages);
                    updateDoc.$set.pagesRead = p;
                } else {
                    updateDoc.$set.pagesRead = 0;
                }
            }

            const result = await libraryCollection.updateOne(
                { _id: new ObjectId(id), userEmail: email },
                updateDoc
            );

            res.send({
                ok: true,
                result,
                progress: {
                    pagesRead: updateDoc.$set.pagesRead,
                    percent: updateDoc.$set.percent,
                    totalPages,
                },
            });
        });

        // REMOVE book from my library
        app.delete("/library/:bookId", verifyToken, async (req, res) => {
            const email = req.user.email;
            const bookId = req.params.bookId;
            const query = { _id: new ObjectId(bookId) };

            const exists = await libraryCollection.findOne({ userEmail: email, bookId });
            if (!exists) {
                return res.status(404).send({ message: "Not found" });
            }

            const result = await libraryCollection.deleteOne({ userEmail: email, bookId });

            // decrease totalShelved
            try {
                await booksCollection.updateOne(
                    query,
                    { $inc: { totalShelved: -1 } }
                );
            } catch {}

            res.send({ ok: true, result });
        });

        /* =========================================================
            Reviews + Pending/Approved + Admin Moderation
        ========================================================= */

        app.get("/reviews", verifyToken, async (req, res) => {
            const { bookId } = req.query;
            if (!bookId) {
                return res.status(400).send({ message: "bookId is required" });
            }

            const result = await reviewsCollection
                .find({ bookId, status: "approved" })
                .sort({ createdAt: -1 })
                .toArray();

            res.send(result);
        });

        app.get("/admin/reviews/approved", verifyToken, verifyAdmin, async (req, res) => {
            const cursor = reviewsCollection.find({ status: "approved" }).sort({ createdAt: -1 });
            const result = await cursor.toArray();
            res.send(result);
        });

        // USER: submit review (pending)
        app.post("/reviews", verifyToken, async (req, res) => {
            const email = req.user.email;
            const { bookId, rating, text } = req.body;
            const query = { _id: new ObjectId(bookId) };

            if (!bookId || rating === undefined || !text) {
                return res.status(400).send({ message: "bookId, rating, text are required" });
            }

            const r = parseFloat(rating);
            if (isNaN(r) || r < 1 || r > 5) {
                return res.status(400).send({ message: "Rating must be between 1 and 5" });
            }

            if (text.trim().length < 10) {
                return res.status(400).send({ message: "Review must be at least 10 characters" });
            }

            // validate book exists
            let book;

            try {
                book = await booksCollection.findOne(query);
            } catch {
                return res.status(400).send({ message: "Invalid bookId" });
            }

            if (!book) {
                return res.status(404).send({ message: "Book not found" });
            }

            // get user info for showing on approved reviews
            const user = await usersCollection.findOne({ email });
            const userName = user?.name || "Anonymous";
            const userPhoto = user?.photo || "";

            // optional rule: one review per user per book
            const exists = await reviewsCollection.findOne({ bookId, userEmail: email });
            if (exists) {
                return res.status(409).send({ message: "You already submitted a review for this book" });
            }

            const newReview = {
                bookId,
                userEmail: email,
                userName,
                userPhoto,
                rating: r,
                text: text.trim(),
                status: "pending",
                createdAt: new Date(),
                updatedAt: new Date(),
            };

            const result = await reviewsCollection.insertOne(newReview);
            res.send({ ok: true, message: "Review submitted for approval", result });
        });

        // USER: get approved reviews for a book
        // GET /reviews/approved?bookId=xxxx
        app.get("/reviews/approved", verifyToken, async (req, res) => {
            const { bookId } = req.query;

            if (!bookId) {
                return res.status(400).send({ message: "bookId is required" });
            }

            const cursor = reviewsCollection.find({ bookId, status: "approved" }).sort({ createdAt: -1 });
            const result = await cursor.toArray();
            res.send(result);
        });

        // ADMIN: list pending reviews
        app.get("/reviews/pending", verifyToken, verifyAdmin, async (req, res) => {
            const cursor = reviewsCollection.find({ status: "pending" }).sort({ createdAt: -1 });
            const result = await cursor.toArray();
            res.send(result);
        });

        // ADMIN: approve a review + recompute book avgRating
        app.patch("/reviews/:id/approve", verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;

            let review;
            try {
                review = await reviewsCollection.findOne({ _id: new ObjectId(id) });
            } catch {
                return res.status(400).send({ message: "Invalid review id" });
            }

            if (!review) {
                return res.status(404).send({ message: "Review not found" });
            }

            if (review.status === "approved") {
                return res.send({ ok: true, message: "Already approved" });
            }

            const result = await reviewsCollection.updateOne(
                { _id: new ObjectId(id) },
                { $set: { status: "approved", updatedAt: new Date() } }
            );

            const newAvg = await recomputeBookAvgRating(review.bookId);

            res.send({
                ok: true,
                message: "Review approved",
                avgRating: newAvg,
                result,
            });
        });

        // ADMIN: delete review (pending/approved both)
        // If approved review deleted => avgRating recompute
        app.delete("/reviews/:id", verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;

            let review;
            try {
                review = await reviewsCollection.findOne({ _id: new ObjectId(id) });
            } catch {
                return res.status(400).send({ message: "Invalid review id" });
            }

            if (!review) {
                return res.status(404).send({ message: "Review not found" });
            }

            const wasApproved = review.status === "approved";
            const bookId = review.bookId;

            const result = await reviewsCollection.deleteOne({ _id: new ObjectId(id) });

            if (wasApproved) {
                await recomputeBookAvgRating(bookId);
            }

            res.send({ ok: true, message: "Review deleted", result });
        });

        /* =========================================================
            USER DASHBOARD STATS
        ========================================================= */

        // GET my dashboard stats
        app.get("/dashboard/me/stats", verifyToken, async (req, res) => {
            const email = req.user.email;

            // library items
            const libraryItems = await libraryCollection.find({ userEmail: email }).toArray();

            const readItems = libraryItems.filter((i) => i.shelf === "read");
            const readingItems = libraryItems.filter((i) => i.shelf === "reading");

            // get books for page calculations
            const ids = libraryItems.map((i) => i.bookId).filter(Boolean).map((id) => new ObjectId(id));
            const books = await booksCollection.find({ _id: { $in: ids } }).toArray();

            const bookMap = {};
            for (const b of books) {
                bookMap[b._id.toString()] = b;
            }

            // pages read
            let totalPagesRead = 0;

            // read shelf => full pages
            for (const it of readItems) {
                const b = bookMap[it.bookId];
                totalPagesRead += b?.totalPages ? parseInt(b.totalPages) : 0;
            }

            // reading shelf => progress pages or percent
            for (const it of readingItems) {
                const b = bookMap[it.bookId];
                const totalPages = b?.totalPages ? parseInt(b.totalPages) : 0;

                if (it.progressType === "pages") {
                    totalPagesRead += parseInt(it.pagesRead || 0);
                } else if (it.progressType === "percent") {
                    totalPagesRead += Math.round((totalPages * (parseFloat(it.percent || 0) / 100)));
                }
            }

            // avg rating given (approved + pending both count as "given")
            const myReviews = await reviewsCollection.find({ userEmail: email }).project({ rating: 1 }).toArray();
            const myAvgRating =
                myReviews.length === 0
                ? 0
                : Math.round(
                    (myReviews.reduce((acc, r) => acc + (parseFloat(r.rating) || 0), 0) / myReviews.length) * 10
                    ) / 10;

            // favorite genre (from read shelf)
            const genreCount = {};
            for (const it of readItems) {
                const b = bookMap[it.bookId];
                if (b?.genreId) {
                    genreCount[b.genreId] = (genreCount[b.genreId] || 0) + 1;
                }
            }

            // top 3 genre ids
            const topGenreIds = Object.entries(genreCount)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 3)
                .map(([gid]) => gid);

            const topGenres = topGenreIds.length
                ? await genresCollection
                    .find({ _id: { $in: topGenreIds.map((id) => new ObjectId(id)) } })
                    .toArray()
                : [];

            res.send({
                readCount: readItems.length,
                readingCount: readingItems.length,
                totalPagesRead,
                avgRatingGiven: myAvgRating,
                favoriteGenres: topGenres.map((g) => ({ id: g._id.toString(), name: g.name, count: genreCount[g._id.toString()] || 0 })),
            });
        });

        /* =========================================================
            TUTORIALS (YouTube links)
        ========================================================= */

        // GET tutorials (logged in)
        app.get("/tutorials", verifyToken, async (req, res) => {
            const cursor = tutorialsCollection.find().sort({ createdAt: -1 });
            const tutorials = await cursor.toArray();

            // add videoId for easy embed in frontend
            const result = tutorials.map((t) => ({
                ...t,
                videoId: getYouTubeVideoId(t.youtubeUrl),
            }));

            res.send(result);
        });

        // ADMIN: add tutorial
        app.post("/tutorials", verifyToken, verifyAdmin, async (req, res) => {
            const { title, youtubeUrl } = req.body;

            if (!title || !title.trim() || !youtubeUrl || !youtubeUrl.trim()) {
                return res.status(400).send({ message: "title and youtubeUrl are required" });
            }

            if (!isYouTubeUrl(youtubeUrl.trim())) {
                return res.status(400).send({ message: "Invalid YouTube URL" });
            }

            const newTutorial = {
                title: title.trim(),
                youtubeUrl: youtubeUrl.trim(),
                createdAt: new Date(),
                updatedAt: new Date(),
            };

            const result = await tutorialsCollection.insertOne(newTutorial);
            res.send({ ok: true, result });
        });

        // ADMIN: update tutorial
        app.patch("/tutorials/:id", verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const { title, youtubeUrl } = req.body;
            const query = { _id: new ObjectId(id) };

            const updateDoc = {
                $set: {
                    updatedAt: new Date()
                }
            };

            if (title && title.trim()) {
                updateDoc.$set.title = title.trim();
            }

            if (youtubeUrl && youtubeUrl.trim()) {
                if (!isYouTubeUrl(youtubeUrl.trim())) {
                    return res.status(400).send({ message: "Invalid YouTube URL" });
                }
                updateDoc.$set.youtubeUrl = youtubeUrl.trim();
            }

            if (Object.keys(updateDoc.$set).length === 1) {
                return res.send({ message: "Nothing to update" });
            }

            try {
                const result = await tutorialsCollection.updateOne(query, updateDoc);
                res.send({ ok: true, result });
            } catch {
                res.status(400).send({ message: "Invalid tutorial id" });
            }
        });

        // ADMIN: delete tutorial
        app.delete("/tutorials/:id", verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };

            try {
                const result = await tutorialsCollection.deleteOne(query);
                res.send({ ok: true, result });
            } catch {
                res.status(400).send({ message: "Invalid tutorial id" });
            }
        });

        // ADMIN: seed 12 default tutorials (optional helper)
        app.post("/tutorials/seed", verifyToken, verifyAdmin, async (req, res) => {
            const count = await tutorialsCollection.countDocuments();
            if (count >= 10) {
                return res.send({ message: "Already seeded (10+ tutorials exist)" });
            }

            const seedData = [
                { title: "How to Read More Books (Practical Tips)", youtubeUrl: "https://www.youtube.com/watch?v=E7Z1gY8cX3w" },
                { title: "Best Books to Start Reading Habit", youtubeUrl: "https://www.youtube.com/watch?v=GQY9nYVxFfU" },
                { title: "How to Choose Your Next Book", youtubeUrl: "https://www.youtube.com/watch?v=7d8wVf4mR5s" },
                { title: "Book Reviews: How to Write Better Reviews", youtubeUrl: "https://www.youtube.com/watch?v=Kk7cR7pTqkI" },
                { title: "Reading Tips: Speed vs Comprehension", youtubeUrl: "https://www.youtube.com/watch?v=0uGm5xw9m2A" },
                { title: "Top Fiction Books Recommendation", youtubeUrl: "https://www.youtube.com/watch?v=7bXkG9bGk7w" },
                { title: "Top Non-Fiction Books Recommendation", youtubeUrl: "https://www.youtube.com/watch?v=Hc5f1oQwD6E" },
                { title: "How to Track Reading Progress", youtubeUrl: "https://www.youtube.com/watch?v=Q4Xh2x1VZ2Y" },
                { title: "Build a Daily Reading Routine", youtubeUrl: "https://www.youtube.com/watch?v=1F3QwYp9pEw" },
                { title: "Must Read Classics (Beginner Friendly)", youtubeUrl: "https://www.youtube.com/watch?v=9qWgJqkK8iM" },
                { title: "Books That Improve Productivity", youtubeUrl: "https://www.youtube.com/watch?v=Vw6s1gWmTtI" },
                { title: "How to Remember What You Read", youtubeUrl: "https://www.youtube.com/watch?v=2Zr8p2mVw6k" },
            ];

            // filter only valid youtube urls (safe)
            const safeSeed = seedData.filter((x) => isYouTubeUrl(x.youtubeUrl));

            const docs = safeSeed.map((x) => ({
                ...x,
                createdAt: new Date(),
                updatedAt: new Date(),
            }));

            const result = await tutorialsCollection.insertMany(docs);
            res.send({ ok: true, insertedCount: result.insertedCount });
        });

        /* =========================================================
            ADMIN DASHBOARD (Stats + Charts)
        ========================================================= */

        app.get("/admin/stats", verifyToken, verifyAdmin, async (req, res) => {
            const totalUsers = await usersCollection.countDocuments();
            const totalBooks = await booksCollection.countDocuments();
            const pendingReviews = await reviewsCollection.countDocuments({ status: "pending" });
            const totalGenres = await genresCollection.countDocuments();
            const totalTutorials = await tutorialsCollection.countDocuments();

            res.send({
                totalUsers,
                totalBooks,
                totalGenres,
                totalTutorials,
                pendingReviews,
            });
        });

        // Chart 1: Books per Genre
        app.get("/admin/charts/books-per-genre", verifyToken, verifyAdmin, async (req, res) => {
            const genres = await genresCollection.find().sort({ name: 1 }).toArray();
            const genreMap = {};
            genres.forEach((g) => (genreMap[g._id.toString()] = g.name));

            const agg = await booksCollection
                .aggregate([
                    {
                        $group: {
                            _id: "$genreId",
                            count: { $sum: 1 },
                        },
                    },
                    {
                        $sort: { count: -1 }
                    },
                ])
                .toArray();

            const labels = agg.map((x) => genreMap[x._id] || "Unknown");
            const data = agg.map((x) => x.count);

            // Recharts friendly too
            const chart = agg.map((x) => ({
                name: genreMap[x._id] || "Unknown",
                value: x.count,
            }));

            res.send({ labels, data, chart });
        });

        // Chart 2: Monthly Books Read (Current Year)
        app.get("/admin/charts/monthly-books-read", verifyToken, verifyAdmin, async (req, res) => {
            const year = parseInt(req.query.year) || new Date().getFullYear();

            const start = new Date(`${year}-01-01T00:00:00.000Z`);
            const end = new Date(`${year + 1}-01-01T00:00:00.000Z`);

            const agg = await libraryCollection
                .aggregate([
                    {
                        $match: { shelf: "read" }
                    },
                    {
                        $addFields: {
                        doneDate: {
                            $ifNull: ["$finishedAt", "$updatedAt"] },
                        },
                    },
                    {
                        $match: {
                            doneDate: { $gte: start, $lt: end }
                        }
                    },
                    {
                        $group: {
                            _id: { $month: "$doneDate" },
                            count: { $sum: 1 },
                        },
                    },
                    {
                        $sort: { "_id": 1 }
                    },
                ])
                .toArray();

            // ensure 12 months
            const months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
            const map = {};
            agg.forEach((x) => (map[x._id] = x.count));

            const labels = months;
            const data = months.map((_, idx) => map[idx + 1] || 0);

            // recharts
            const chart = months.map((m, idx) => ({
                month: m,
                books: map[idx + 1] || 0,
            }));

            res.send({ year, labels, data, chart });
        });

        // Chart 3: Monthly Pages Read (Current Year)
        app.get("/admin/charts/pages-read-monthly", verifyToken, verifyAdmin, async (req, res) => {
            const year = parseInt(req.query.year) || new Date().getFullYear();

            const start = new Date(`${year}-01-01T00:00:00.000Z`);
            const end = new Date(`${year + 1}-01-01T00:00:00.000Z`);

            const agg = await libraryCollection
                .aggregate([
                    { $match: { shelf: "read" } },
                    {
                        $addFields: {
                        doneDate: { $ifNull: ["$finishedAt", "$updatedAt"] },
                        },
                    },
                    {
                        $match: {
                            doneDate: { $gte: start, $lt: end }
                        }
                    },

                    // join book to get totalPages
                    {
                        $lookup: {
                            from: "books",
                            let: { bid: "$bookId" },
                            pipeline: [
                                {
                                    $match: {
                                        $expr: {
                                            $eq: ["$_id", { $toObjectId: "$$bid" }]
                                        },
                                    },
                                },
                                {
                                    $project: { totalPages: 1 }
                                },
                            ],
                            as: "book",
                        },
                    },
                    {
                        $unwind: {
                            path: "$book", preserveNullAndEmptyArrays: true
                        }
                    },

                    {
                        $group: {
                            _id: { $month: "$doneDate" },
                            pages: {
                                $sum: { $ifNull: ["$book.totalPages", 0] }
                            },
                        },
                    },
                    {
                        $sort: { "_id": 1 }
                    },
                ])
            .toArray();

            const months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
            const map = {};
            agg.forEach((x) => (map[x._id] = x.pages));

            const labels = months;
            const data = months.map((_, idx) => map[idx + 1] || 0);

            const chart = months.map((m, idx) => ({
                month: m,
                pages: map[idx + 1] || 0,
            }));

            res.send({ year, labels, data, chart });
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

app.get("/", (req, res) => {
    res.send("Book Worm server side is running!");
});

app.listen(port, () => {
    console.log(
        `Book Worm listening on ${process.env.PROTOCOL}://${process.env.HOST}:${process.env.PORT}`,
    );
});
