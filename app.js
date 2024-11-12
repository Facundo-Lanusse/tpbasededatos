const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const ejs = require('ejs');
const path = require('path');
const bodyParser = require('body-parser');
const app = express();
const session = require('express-session');
const port = process.env.PORT || 3000;

app.use(session({
    secret: 'tu_clave_secreta', // Cambia esto a una cadena única y segura
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Cambia a true si usas HTTPS
}));

// Middleware para pasar el usuario a todas las vistas
app.use((req, res, next) => {
    res.locals.user = req.session.user || null; // Esto hace que `user` esté disponible en todas las vistas
    next();
});

// Servir archivos estáticos desde el directorio "views"
app.use(express.static('views'));

// Usa rutas relativas dentro del proyecto
const dbPath = path.resolve(__dirname, './movies.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error("Error conectando a la base de datos:", err);
    } else {
        console.log("Conectado a la base de datos de películas.");

        // Creación de la nueva tabla users
        const createUserTable = `
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_username TEXT UNIQUE NOT NULL,
                user_name TEXT NOT NULL,
                user_email TEXT UNIQUE NOT NULL,
                user_password TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0
            );
        `;
        const createMovieUserTable = `
            CREATE TABLE IF NOT EXISTS movie_user (
            movie_user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            movie_id INTEGER NOT NULL,
            rating INTEGER CHECK(rating >= 1 AND rating <= 10),
            review TEXT,
            FOREIGN KEY (user_id) REFERENCES users(user_id),
            FOREIGN KEY (movie_id) REFERENCES movie(movie_id)
            );
        `;
        db.run(createMovieUserTable, (err) => {
            if (err) {
                console.error("Error creando la tabla de Movie_usuarios:", err);
            } else {
                console.log("Tabla de Movie_usuarios creada o ya existe.");
            }
        });

        db.run(createUserTable, (err) => {
            if (err) {
                console.error("Error creando la tabla de usuarios:", err);
            } else {
                console.log("Tabla de usuarios creada o ya existe.");
            }
        });
    }
});


// Middleware para analizar el cuerpo de las solicitudes POST
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json()); // Para analizar solicitudes JSON si es necesario

app.get('/', (req, res) => {
    const isAuthenticated = req.session.user !== undefined;
    const isAdmin = req.session.user && req.session.user.is_admin === 1;

    res.render('index', { isAuthenticated, isAdmin});
});

app.get('/login', (req, res) => {
    res.render('login', { isAuthenticated: !!req.session.user });
});

app.get('/signup', (req, res) => {
    res.render('signup', { isAuthenticated: !!req.session.user });
});

// Middleware para verificar si el usuario está autenticado
function isAuthenticated(req, res, next) {
    if (req.session.user) {
        next(); // Permitir acceso
    } else {
        res.status(401).send('Debe iniciar sesión para realizar esta acción.');
    }
}
// Middleware para verificar si el usuario es administrador

function isAdmin(req, res, next) {
    // Simulación del usuario actual (esto debería implementarse con un sistema de autenticación real)
    const currentUser = req.session.user || { is_admin: 0 }; // Obtener el usuario actual de la sesión

    if (currentUser.is_admin) {
        next(); // Permitir acceso
    } else {
        res.status(403).send('Acceso denegado. Se requieren permisos de administrador.');
    }
}
// Configurar el motor de plantillas EJS
app.set('view engine', 'ejs');

// Listar usuarios (solo para administradores)
app.get('/users', isAdmin, (req, res) => {
    const getUsersQuery = `SELECT user_id, user_username, user_name, user_email FROM users`;
    db.all(getUsersQuery, (err, rows) => {
        if (err) {
            console.error("Error al obtener la lista de usuarios:", err);
            return res.status(500).send('Error al obtener la lista de usuarios.');
        }
        res.render('users', { users: rows });
    });
});

// Eliminar usuario (solo para administradores)
app.post('/users/:id/delete', isAdmin, (req, res) => {
    const userId = req.params.id;
    const deleteUserQuery = `DELETE FROM users WHERE user_id = ?`;
    db.run(deleteUserQuery, [userId], (err) => {
        if (err) {
            console.error("Error al eliminar el usuario:", err);
            return res.status(500).send('Error al eliminar el usuario.');
        }
        res.redirect('/users?message=Usuario eliminado con éxito');
    });
});
// Ruta para la página de registro
app.get('/signup', (req, res) => {
    res.render('signup'); // Renderiza el formulario de registro
});

// Ruta para manejar el registro de usuarios
app.post('/signup', (req, res) => {
    const { user_name, username, user_email, user_password } = req.body;

    if (!user_name || !username || !user_email || !user_password) {
        return res.status(400).send("Todos los campos son obligatorios.");
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(user_email)) {
        return res.status(400).send("Correo electrónico no válido.");
    }

    const checkUserQuery = `SELECT COUNT(*) as count FROM users`;
    db.get(checkUserQuery, [], (err, row) => {
        if (err) {
            console.error("Error al verificar el número de usuarios:", err);
            return res.status(500).send("Error al registrar el usuario.");
        }

        const is_admin = row.count === 0 ? 1 : 0;

        const insertUserQuery = `
            INSERT INTO users (user_name, user_username, user_email, user_password, is_admin)
            VALUES (?, ?, ?, ?, ?);
        `;

        db.run(insertUserQuery, [user_name, username, user_email, user_password, is_admin], function (err) {
            if (err) {
                console.error("Error al registrar el usuario:", err);
                return res.status(500).send("Error al registrar el usuario.");
            }

            // Aquí es donde se produce el error
            req.session.user = {
                user_id: this.lastID,
                user_name: user_name,
                user_username: username,
                is_admin: is_admin
            };

            console.log("Usuario registrado exitosamente con user_id:", this.lastID);
            res.redirect('/login');
        });
    });
});

// Ruta para la página de inicio de sesión
app.get('/login', (req, res) => {
    res.render('login'); // Renderiza el formulario de inicio de sesión
});

// Ruta para manejar el inicio de sesión
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    const checkUserQuery = `SELECT * FROM users WHERE user_username = ?`;
    db.get(checkUserQuery, [username], (err, row) => {
        if (err) {
            console.error("Error al verificar el usuario:", err);
            return res.status(500).send("Error al iniciar sesión.");
        }
        if (!row || row.user_password !== password) {
            return res.status(401).send("Nombre de usuario o contraseña incorrectos.");
        }

        req.session.user = {
            user_id: row.user_id,
            user_name: row.user_name,
            user_username: row.user_username,
            is_admin: row.is_admin
        };

        console.log("Inicio de sesión exitoso para el usuario:", username);
        res.redirect('/');
    });
});


// Asociar una película a un usuario autenticado con puntuación y reseña
app.post('/movies', isAuthenticated, (req, res) => {
    const userId = req.session.user.user_id;
    const { movie_id, rating, review } = req.body;
    const insertMovieUserQuery = `
        INSERT INTO movie_user (user_id, movie_id, rating, review)
        VALUES (?, ?, ?, ?);
    `;
    db.run(insertMovieUserQuery, [userId, movie_id, rating, review], (err) => {
        if (err) {
            console.error("Error al asociar la película con el usuario:", err);
            return res.status(500).send('Error al asociar la película con el usuario.');
        }
        res.send('Película asociada con éxito');
    });
});

// Actualizar reseña y puntuación de una película para el usuario autenticado
app.put('/movies/:movieUserId', isAuthenticated, (req, res) => {
    const userId = req.session.user.user_id;
    const { movieUserId } = req.params;
    const { rating, review } = req.body;
    const updateMovieUserQuery = `
        UPDATE movie_user
        SET rating = ?, review = ?
        WHERE movie_user_id = ? AND user_id = ?;
    `;
    db.run(updateMovieUserQuery, [rating, review, movieUserId, userId], (err) => {
        if (err) {
            console.error("Error al actualizar la reseña o puntuación:", err);
            return res.status(500).send('Error al actualizar la reseña o puntuación.');
        }
        res.send('Reseña y puntuación actualizadas con éxito');
    });
});

// Eliminar la reseña de una película para el usuario autenticado
app.delete('/movies/:movieUserId', isAuthenticated, (req, res) => {
    const userId = req.session.user.user_id;
    const { movieUserId } = req.params;
    const deleteMovieUserQuery = `DELETE FROM movie_user WHERE movie_user_id = ? AND user_id = ?`;
    db.run(deleteMovieUserQuery, [movieUserId, userId], (err) => {
        if (err) {
            console.error("Error al eliminar la reseña de la película:", err);
            return res.status(500).send('Error al eliminar la reseña de la película.');
        }
        res.send('Reseña eliminada con éxito');
    });
});

// Ruta para la página de inicio
app.get('/', (req, res) => {
    res.render('index');
});

// Búsqueda de películas, actores, directores, palabras clave y todo
app.get('/buscar', (req, res) => {
    const searchTerm = req.query.q;
    const type = req.query.type;
    const params = [`%${searchTerm}%`];

    let movieQuery = `SELECT 'movie' as type, title as name, movie_id as id FROM movie WHERE title LIKE ?`;
    let actorQuery = `
        SELECT DISTINCT 'actor' as type, person_name as name, p.person_id as id 
        FROM person p
        INNER JOIN movie_cast mc on p.person_id = mc.person_id
        WHERE person_name LIKE ?`;
    let directorQuery = `
        SELECT DISTINCT 'director' as type, person_name as name, p.person_id as id 
        FROM person p
        INNER JOIN movie_crew mcr on p.person_id = mcr.person_id
        WHERE job = 'Director' AND person_name LIKE ?`;
    let keywordQuery = `
        SELECT DISTINCT 'keyword' as type, m.title as name, m.movie_id as id
        FROM movie m
        INNER JOIN movie_keywords mk ON m.movie_id = mk.movie_id
        INNER JOIN keyword k ON mk.keyword_id = k.keyword_id
        WHERE keyword_name LIKE ?`;

    if (type === 'movie') {
        db.all(movieQuery, params, (err, rows) => {
            if (err) {
                console.error(err);
                return res.status(500).send('Error en la búsqueda.');
            }
            res.render('resultado', { results: rows, searchTerm, type });
        });
    } else if (type === 'actor') {
        db.all(actorQuery, params, (err, rows) => {
            if (err) {
                console.error(err);
                return res.status(500).send('Error en la búsqueda.');
            }
            res.render('resultado', { results: rows, searchTerm, type });
        });
    } else if (type === 'director') {
        db.all(directorQuery, params, (err, rows) => {
            if (err) {
                console.error(err);
                return res.status(500).send('Error en la búsqueda.');
            }
            res.render('resultado', { results: rows, searchTerm, type });
        });
    } else if (type === 'keyword') {
        db.all(keywordQuery, params, (err, rows) => {
            if (err) {
                console.error(err);
                return res.status(500).send('Error en la búsqueda.');
            }
            res.render('resultado', { results: rows, searchTerm, type });
        });
    } else if (type === 'todo') {
        // Ejecutar las consultas para películas, actores y directores en paralelo
        let results = [];

        // Ejecutar la consulta de películas
        db.all(movieQuery, params, (err, movieRows) => {
            if (err) {
                console.error(err);
                return res.status(500).send('Error en la búsqueda de películas.');
            }
            results = results.concat(movieRows);

            // Ejecutar la consulta de actores
            db.all(actorQuery, params, (err, actorRows) => {
                if (err) {
                    console.error(err);
                    return res.status(500).send('Error en la búsqueda de actores.');
                }
                results = results.concat(actorRows);

                // Ejecutar la consulta de directores
                db.all(directorQuery, params, (err, directorRows) => {
                    if (err) {
                        console.error(err);
                        return res.status(500).send('Error en la búsqueda de directores.');
                    }
                    results = results.concat(directorRows);

                    // Finalmente renderizar los resultados combinados
                    res.render('resultado', { results, searchTerm, type });
                });
            });
        });
    } else {
        return res.status(400).send('Tipo de búsqueda no válido. Debe ser "movie", "actor", "director", "keyword" o "todo".');
    }
});

// Ruta para la página de datos de una película particular
app.get('/pelicula/:id', (req, res) => {
    const movieId = req.params.id;
    const movieQuery = `SELECT * FROM movie WHERE movie_id = ?`;
    const commentsQuery = `
    SELECT u.user_name, mu.rating, mu.review
    FROM movie_user mu
    JOIN users u ON mu.user_id = u.user_id
    WHERE mu.movie_id = ?
    ORDER BY mu.movie_user_id DESC
`;
const averageRatingQuery = `
    SELECT AVG(mu.rating) AS average_rating
    FROM movie_user mu
    WHERE mu.movie_id = ?
`;
    const castQuery = `
        SELECT actor.person_name AS actor_name, actor.person_id AS actor_id, movie_cast.character_name, movie_cast.cast_order
        FROM movie_cast 
        LEFT JOIN person AS actor ON movie_cast.person_id = actor.person_id
        WHERE movie_cast.movie_id = ?`;
    const crewQuery = `
        SELECT crew_member.person_name AS crew_member_name, crew_member.person_id AS crew_member_id, department.department_name, movie_crew.job
        FROM movie_crew 
        LEFT JOIN department ON movie_crew.department_id = department.department_id
        LEFT JOIN person AS crew_member ON crew_member.person_id = movie_crew.person_id
        WHERE movie_crew.movie_id = ?`;
    const genreQuery = `SELECT genre.genre_name FROM movie_genres LEFT JOIN genre ON movie_genres.genre_id = genre.genre_id WHERE movie_genres.movie_id = ?`;
    const productionCompanyQuery = `
    SELECT production_company.company_name AS company_name
    FROM movie_company
    LEFT JOIN production_company ON movie_company.company_id = production_company.company_id
    WHERE movie_company.movie_id = ?;
`;
    const languageQuery = `SELECT language.language_name FROM movie_languages LEFT JOIN language ON movie_languages.language_id = language.language_id WHERE movie_languages.movie_id = ?`;
    const countryQuery = `SELECT country.country_name FROM production_country LEFT JOIN country ON production_country.country_id = country.country_id WHERE production_country.movie_id = ?`;
    const keywordQuery = `SELECT keyword.keyword_name FROM movie_keywords LEFT JOIN keyword ON movie_keywords.keyword_id = keyword.keyword_id WHERE movie_keywords.movie_id = ?`;

    // Ejecutar la consulta de la película
    db.get(movieQuery, [movieId], (err, movieRow) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error al cargar los datos de la película.');
        }
        if (!movieRow) {
            return res.status(404).send('Película no encontrada.');
        }

        const movieData = {
            id: movieRow.movie_id,
            title: movieRow.title,
            release_date: movieRow.release_date,
            overview: movieRow.overview,
            directors: [],
            writers: [],
            cast: [],
            crew: [],
            genres: [],
            company_name: [],
            languages: [],
            countries: [],
            keywords: []
        };

        // Ejecutar las consultas restantes
        const queries = [
            {query: castQuery, target: 'cast'},
            {query: crewQuery, target: 'crew'},
            {query: genreQuery, target: 'genres'},
            {query: productionCompanyQuery, target: 'company_name'},
            {query: languageQuery, target: 'languages'},
            {query: countryQuery, target: 'countries'},
            {query: keywordQuery, target: 'keywords'}
        ];

        let completedQueries = 0;

        // Ejecutar todas las consultas en paralelo
        queries.forEach(({query, target}) => {
            db.all(query, [movieId], (err, rows) => {
                if (err) {
                    console.error(err);
                } else {
                    if (target === 'cast') {
                        rows.forEach(row => {
                            movieData.cast.push({
                                actor_id: row.actor_id,
                                actor_name: row.actor_name,
                                character_name: row.character_name,
                                cast_order: row.cast_order,
                            });
                        });
                    } else if (target === 'crew') {
                        rows.forEach(row => {
                            if (row.job === 'Director') {
                                movieData.directors.push({
                                    crew_member_id: row.crew_member_id,
                                    crew_member_name: row.crew_member_name
                                });
                            } else if (row.job === 'Writer') {
                                movieData.writers.push({
                                    crew_member_id: row.crew_member_id,
                                    crew_member_name: row.crew_member_name
                                });
                            } else {
                                movieData.crew.push({
                                    crew_member_id: row.crew_member_id,
                                    crew_member_name: row.crew_member_name,
                                    department_name: row.department_name,
                                    job: row.job,
                                });
                            }
                        });
                    } else if (target === 'company_name') {
                        rows.forEach(row => {
                            movieData.company_name.push(row.company_name);
                        });
                    } else if (target === 'countries') {
                        rows.forEach(row => {
                            movieData.countries.push(row.country_name);
                        });
                    } else {
                        const uniqueItems = [...new Set(rows.map(row => row[target.slice(0, -1) + '_name']))];
                        movieData[target] = uniqueItems;
                    }
                }

                completedQueries++;
                if (completedQueries === queries.length) {
                   // Ejecutar la consulta para obtener el puntaje promedio
                    db.get(averageRatingQuery, [movieId], (err, avgRatingRow) => {
                        if (err) {
                            console.error("Error al cargar el puntaje promedio:", err);
                            return res.status(500).send("Error al cargar el puntaje promedio.");
                        }

                        // Asignar el puntaje promedio a la variable movieData
                        const averageRating = avgRatingRow ? avgRatingRow.average_rating : null;

                        // Añadir la información de puntajes a movieData
                        movieData.average_rating = averageRating;

                        // Ahora, continuar con la carga de comentarios y renderizar la vista
                        db.all(commentsQuery, [movieId], (err, comments) => {
                            if (err) {
                                console.error("Error al cargar los comentarios:", err);
                                return res.status(500).send("Error al cargar los comentarios.");
                            }
                            
                            res.render('pelicula', { movie: movieData, comments });
                        });
                    });
                }
            });
        });
    });
});
// Ruta para mostrar la página de un actor específico
app.get('/actor/:id', (req, res) => {
    const actorId = req.params.id;

    // Consultas para películas en las que actuó y dirigió
    const actingQuery = `
        SELECT DISTINCT person.person_name as actorName, movie.* 
        FROM movie  
        INNER JOIN movie_cast ON movie.movie_id = movie_cast.movie_id
        INNER JOIN person ON person.person_id = movie_cast.person_id
        WHERE movie_cast.person_id = ?
    `;
    const directingQuery = `
        SELECT DISTINCT movie.* 
        FROM movie
        INNER JOIN movie_crew ON movie.movie_id = movie_crew.movie_id
        INNER JOIN person ON person.person_id = movie_crew.person_id
        WHERE movie_crew.job = 'Director' AND movie_crew.person_id = ?
    `;

    db.all(actingQuery, [actorId], (err, actingMovies) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error al cargar las películas del actor.');
        }
        db.all(directingQuery, [actorId], (err, directingMovies) => {
            if (err) {
                console.error(err);
                return res.status(500).send('Error al cargar las películas como director.');
            }

            const actorName = actingMovies.length > 0 ? actingMovies[0].actorName : (directingMovies[0] ? directingMovies[0].actorName : '');
            res.render('actor', { actorName, actingMovies, directingMovies });
        });
    });
});

app.get('/director/:id', (req, res) => {
    const directorId = req.params.id;

    // Consultas para películas en las que actuó y dirigió
    const directingQuery = `
        SELECT DISTINCT person.person_name as directorName, movie.* 
        FROM movie
        INNER JOIN movie_crew ON movie.movie_id = movie_crew.movie_id
        INNER JOIN person ON person.person_id = movie_crew.person_id
        WHERE movie_crew.job = 'Director' AND movie_crew.person_id = ?
    `;
    const actingQuery = `
        SELECT DISTINCT movie.* 
        FROM movie
        INNER JOIN movie_cast ON movie.movie_id = movie_cast.movie_id
        INNER JOIN person ON person.person_id = movie_cast.person_id
        WHERE movie_cast.person_id = ?
    `;
    db.all(directingQuery, [directorId], (err, directingMovies) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error al cargar las películas del director.');
        }
        db.all(actingQuery, [directorId], (err, actingMovies) => {
            if (err) {
                console.error(err);
                return res.status(500).send('Error al cargar las películas como actor.');
            }

            const directorName = directingMovies.length > 0 ? directingMovies[0].directorName : (actingMovies[0] ? actingMovies[0].directorName : '');
            res.render('director', { directorName, actingMovies, directingMovies });
        });
    });
});

// Voy al login page
app.get('/login', (req, res) => {
    res.render('login');
});
// Ruta para cerrar sesión
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error("Error al cerrar la sesión:", err);
            return res.status(500).send("Error al cerrar la sesión.");
        }
        res.redirect('/login');
    });
});

// Iniciar el servidor
app.listen(port, () => {
    console.log(`Servidor en ejecución en http://localhost:${port}`);
});
