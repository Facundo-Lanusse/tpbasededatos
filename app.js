const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const ejs = require('ejs');
const path = require('path');
const bodyParser = require('body-parser');
const app = express();
const port = process.env.PORT || 3000;

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
                user_password TEXT NOT NULL
            );
        `;

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

// Configurar el motor de plantillas EJS
app.set('view engine', 'ejs');

// Ruta para la página de registro
app.get('/signup', (req, res) => {
    res.render('signup'); // Renderiza el formulario de registro
});

// Ruta para manejar el registro de usuarios
app.post('/signup', (req, res) => {
    const { user_name, username, user_email, user_password } = req.body;

    // Validar que los campos no estén vacíos
    if (!user_name || !username || !user_email || !user_password) {
        return res.status(400).send("Todos los campos son obligatorios.");
    }

    // Verifica si el formato del correo electrónico es válido
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(user_email)) {
        return res.status(400).send("Correo electrónico no válido.");
    }

    // Primero, verifica si el nombre de usuario o el correo electrónico ya existen
    const checkUserQuery = `SELECT * FROM users WHERE user_username = ? OR user_email = ?`;
    db.get(checkUserQuery, [username, user_email], (err, row) => {
        if (err) {
            console.error("Error al verificar el usuario:", err);
            return res.status(500).send("Error al registrar el usuario.");
        }
        if (row) {
            // Si se encontró un usuario con el mismo nombre de usuario o correo electrónico
            return res.status(400).send("El nombre de usuario o el correo electrónico ya existen.");
        }

        // Inserta los datos del usuario en la tabla de usuarios
        const insertUserQuery = `
            INSERT INTO users (user_name, user_username, user_email, user_password)
            VALUES (?, ?, ?, ?);
        `;

        db.run(insertUserQuery, [user_name, username, user_email, user_password], function (err) {
            if (err) {
                console.error("Error al registrar el usuario:", err);
                return res.status(500).send("Error al registrar el usuario.");
            }

            console.log("Usuario registrado exitosamente con user_id:", this.lastID);
            // Redirigir a la página anterior
            const referer = req.headers.referer || '/'; // Fallback a la raíz si no hay referer
            res.redirect(referer); // Redirige a la página anterior
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

    // Verificar si el nombre de usuario y la contraseña son correctos
    const checkUserQuery = `SELECT * FROM users WHERE user_username = ?`;
    db.get(checkUserQuery, [username], (err, row) => {
        if (err) {
            console.error("Error al verificar el usuario:", err);
            return res.status(500).send("Error al iniciar sesión.");
        }
        if (!row) {
            // Si no se encontró el usuario
            return res.status(401).send("Nombre de usuario o contraseña incorrectos.");
        }

        // Aquí debes comparar las contraseñas
        // Si usas texto plano, simplemente compara directamente
        if (row.user_password !== password) {
            return res.status(401).send("Nombre de usuario o contraseña incorrectos.");
        }

        console.log("Inicio de sesión exitoso para el usuario:", username);
        // Redirigir a la página anterior
        const referer = req.headers.referer || '/';
        res.redirect(referer); // Redirige a la página anterior
    });
});


// Ruta para la página de inicio
app.get('/', (req, res) => {
    res.render('index');
});

// Búsqueda de películas, actores, directores y palabras clave
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
                        // Asegurarse de que se procesen correctamente las compañías
                        rows.forEach(row => {
                            movieData.company_name.push(row.company_name);
                        });
                    } else if (target === 'countries') {
                        // Asegurarse de que se procesen correctamente los países
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
                    res.render('pelicula', {movie: movieData});
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

// Iniciar el servidor
app.listen(port, () => {
    console.log(`Servidor en ejecución en http://localhost:${port}`);
});
