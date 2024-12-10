/////////////// Configuración general /////////////


import express from 'express'; 
import path from 'path'; 
import { fileURLToPath } from 'url'; // Para obtener la URL del archivo actual
import { engine } from 'express-handlebars'; 
import session from 'express-session'; 
import { neon } from '@neondatabase/serverless'; // Conexión a la base de datos Neon

const app = express();
const __filename = fileURLToPath(import.meta.url); // Ruta del archivo actual
const __dirname = path.dirname(__filename); // Directorio del archivo actual

// Configuración del motor de plantillas Handlebars , para que vea eso de la capeta view 
app.engine('handlebars', engine({
  layoutsDir: path.join(__dirname, 'views', 'layouts'),
  defaultLayout: 'main',
  partialsDir: path.join(__dirname, 'views', 'partials'),
}));
app.set('view engine', 'handlebars');
app.set('views', path.join(__dirname, 'views'));

// Middleware para archivos estáticos y datos JSON
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Configuración de sesiones
app.use(session({
  secret: 'tu_secreto',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false },
}));

// Conexión a la base de datos
const sql = neon('postgresql://Entrega%202_owner:w57DJprGlIMu@ep-steep-cake-a504nuip.us-east-2.aws.neon.tech/Entrega%202?sslmode=require');

/////////////// Manejo de usuarios (Registro y Login) /////////////
import bcrypt from 'bcryptjs'; // Para encriptar las contraseñas
import jwt from 'jsonwebtoken'; // Para generar tokens JWT
import validator from 'validator'; // Pa validar correos electrónicos ( pq pide en la rubirca)

const JWT_SECRET = 'tu_secreto_jwt'; 

// Ruta para la página de login de usuario
app.get('/login', (req, res) => {
  res.render('login', { title: 'Iniciar Sesión', user: req.session.user });
});

// Registro de usuario
app.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;

  // Validar el correo electrónico... aca entra eso de import validator from 'validator'
  if (!validator.isEmail(email)) {
    return res.status(400).json({ error: 'Correo electrónico no válido' });
  }

  const existingUserQuery = 'SELECT * FROM users WHERE email = $1';
  try {
    const existingUserResults = await sql(existingUserQuery, [email]);
    if (existingUserResults.length > 0) {
      return res.status(400).json({ error: 'El correo ya está registrado' });
    }

    const hash = bcrypt.hashSync(password, 5);
    const query = 'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id';
    await sql(query, [name, email, hash]);
    res.redirect('/login'); // Redirige a la página de login
  } catch (error) {
    console.error('Error al registrar usuario:', error);
    res.redirect('/login?error=alreadyRegistered');
  }
});

// Login de usuario


//se revice el POST se los fromularios
// Login de usuario
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const query = 'SELECT * FROM users WHERE email = $1';
  try {
      const results = await sql(query, [email]);
      if (results.length > 0) {
          const user = results[0];
          const isMatch = bcrypt.compareSync(password, user.password);

          if (isMatch) {
              // Almacenar el ID y el nombre en la sesión
              req.session.user = { id: user.id, name: user.name }; // Aquí se almacena el ID
              res.redirect('/');
          } else {
              res.render('login', { title: 'Iniciar Sesión', error: 'Correo o contraseña inválidos.' });
          }
      } else {
          res.render('login', { title: 'Iniciar Sesión', error: 'Correo o contraseña inválidos.' });
      }
  } catch (error) {
      console.error('Error al iniciar sesión:', error);
      res.render('login', { title: 'Iniciar Sesión', error: 'Error en la base de datos.' });
  }
});
// Cerrar sesión de usuario
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.log(err);
    }
    res.redirect('/');
  });
});




/////////////// Administración /////////////
// Ruta para la página de administración
app.get('/administracion', (req, res) => {
  res.render('administracion', { title: 'Administración', user: req.session.user });
});

// Login de administrador
app.post('/admin/login', async (req, res) => {
  const { username, password } = req.body;
  const query = 'SELECT * FROM administradores WHERE nombre = $1';

  try {
    const results = await sql(query, [username]);
    if (results.length > 0) {
      const admin = results[0];

      // Verificar la contraseña
      if (password === admin.contrasena) {
        req.session.admin = true; // verifica ue es admin
        req.session.username = admin.nombre;
        return res.redirect('/contenido');
      } else {
        return res.render('administracion', { error: 'Usuario o contraseña incorrectos.', admin: false });
      }
    } else {
      return res.render('administracion', { error: 'Usuario o contraseña incorrectos.', admin: false });
    }
  } catch (error) {
    console.error('Error al iniciar sesión de administrador:', error);
    return res.render('administracion', { error: 'Error en la base de datos.', admin: false });
  }
});

// Ruta para contenido de administración
app.get('/contenido', async (req, res) => {
  if (req.session.admin) {
    const username = req.session.username || 'Usuario';

    try {
      // Obtener total de ventas (suma de la columna 'total')
      const totalSalesResult = await sql('SELECT SUM(total) AS totalsales FROM ventas');
      const totalSales = totalSalesResult[0]?.totalsales || 0;

      // Obtener datos de la tabla ventas con información del producto
      const ventasResult = await sql(`
        SELECT v.user_id, v.producto_id, v.total, v.fecha, u.name, p.nombre AS nombre_producto, p.imagen AS imagen_producto, p.precio
        FROM ventas v
        JOIN users u ON v.user_id = u.id
        JOIN productos p ON v.producto_id = p.id
      `);

      // Renderizar la vista con el total de ventas y los datos de ventas
      res.render('contenido', {
        title: 'Administración',
        username: username,
        admin: true,
        totalSales: parseFloat(totalSales).toLocaleString('de-DE', { minimumFractionDigits: 0 }),
        sales: ventasResult,
      });
    } catch (error) {
      console.error('Error al obtener datos de administración:', error);
      res.status(500).send('Error en el servidor.');
    }
  } else {
    res.redirect('/administracion');
  }
});

// ruta de eliminacion de productos 

// Ruta para eliminar productos (GET) 
// es get pq no envia info o para modificar solo pide informacion paar ver 
app.get('/eliminar', async (req, res) => {
  if (req.session.admin) {
    try {
      // Obtener todos los productos
      const productosResult = await sql('SELECT id AS producto_id, nombre AS name, precio, imagen FROM productos');

      res.render('eliminar', {
        title: 'Eliminar Producto',
        username: req.session.username || 'Usuario',
        admin: true,
        productos: productosResult,
      });
    } catch (error) {
      console.error('Error al obtener productos:', error);
      res.status(500).send('Error en el servidor.');
    }
  } else {
    res.redirect('/administracion');
  }
});

// Ruta para eliminar un producto (POST) , envia enformacin en este caso el id del producto a eliminar 
/// aca aparte de eliminar el prodcuto de la tabla de productos , igual lo elimina de la tabla de ventas , 
app.post('/eliminar_producto', async (req, res) => {
  const { id } = req.body; // Obtener el ID del producto del cuerpo de la solicitud
  console.log('ID del producto a eliminar:', id); // Verificar el ID recibido

  try {
    // Verificar si el producto existe
    const productoExistente = await sql('SELECT * FROM productos WHERE id = $1', [id]); 
    if (productoExistente.length === 0) {
      return res.status(404).send('Producto no encontrado');
    }

    // Eliminar el producto de la base de datos
    await sql('DELETE FROM productos WHERE id = $1', [id]); 
    console.log('Producto eliminado:', id); // Confirmación de eliminación

    res.redirect('/eliminar'); // Redirigir de nuevo a la página de eliminación
  } catch (error) {
    console.error('Error al eliminar producto:', error);
    res.status(500).send('Error en el servidor.');
  }
});

//////////////////////modificar el producto ///////////////


// Ruta para modificar productos  
// aca igual lo modifica de la tabla de venta .... , por ende el problema es que el precio que el usario pago no seria ese , sino que otro 
// ver una forma de areglarlo , sino hacer otra tabla de ventas




//lista todos los productos que pueden ser modificados por el administrador.

app.get('/modificar', async (req, res) => {
  if (req.session.admin) {
    try {
      // Obtener todos los productos
      const productosResult = await sql('SELECT id AS producto_id, nombre AS name, precio, imagen, descripcion FROM productos');

      res.render('modificar', {
        title: 'Modificar Producto',
        username: req.session.username || 'Usuario',
        admin: true,
        productos: productosResult, // Pasar la lista de productos a la vista
      });
    } catch (error) {
      console.error('Error al obtener productos:', error);
      res.status(500).send('Error en el servidor.');
    }
  } else {
    res.redirect('/administracion');
  }
});


// Ruta para mostrar la vista de modificar producto (GET)

//se utiliza para obtener y mostrar los detalles de un producto  se desea modificar. vista
// los detalles de un producto específico 
app.get('/modificar_producto/:id', async (req, res) => {
  const { id } = req.params; // Obtener el ID del producto de los parámetros de la URL

  if (req.session.admin) {
    try {
      // Obtener el producto específico por ID
      const productoResult = await sql('SELECT * FROM productos WHERE id = $1', [id]);
      
      if (productoResult.length === 0) {
        return res.status(404).send('Producto no encontrado');
      }

      res.render('modificar_producto', {
        title: 'Modificar Producto',
        username: req.session.username || 'Usuario',
        admin: true,
        producto: productoResult[0], // Pasar el producto encontrado a la vista
      });
    } catch (error) {
      console.error('Error al obtener producto:', error);
      res.status(500).send('Error en el servidor.');
    }
  } else {
    res.redirect('/administracion');
  }
});

// Ruta para modificar un producto (POST)
//procesar la modificación del producto después de que se han hecho cambios en el formulario.
app.post('/modificar_producto', async (req, res) => {
  const { id, nombre, precio, imagen, descripcion } = req.body;

  try {
    await sql('UPDATE productos SET nombre = $1, precio = $2, imagen = $3, descripcion = $4 WHERE id = $5', [nombre, precio, imagen, descripcion, id]);
    console.log('Producto modificado:', id);
    res.redirect('/modificar'); // Redirigir de nuevo a la página de modificación
  } catch (error) {
    console.error('Error al modificar producto:', error);
    res.status(500).send('Error en el servidor.');
  }
});



/////////////// Productos /////////////

// Ruta para la página de crear producto
app.get('/crear_producto', (req, res) => {
  if (req.session.admin) {
    res.render('crear_producto', { title: 'Crear Producto', admin: req.session.admin });
  } else {
    res.redirect('/administracion');
  }
});

app.post('/crear_producto', async (req, res) => {
  const { name, image, description, price } = req.body; // Ya no se incluye 'stock'

  const query = 'INSERT INTO productos (nombre, imagen, descripcion, precio) VALUES ($1, $2, $3, $4)';
  try {
    await sql(query, [name, image, description, price]);
    console.log('Producto creado con éxito');
    res.redirect('/contenido');
  } catch (error) {
    console.error('Error al crear producto:', error);
    res.render('crear_producto', { title: 'Crear Producto', error: 'Error al crear el producto', admin: req.session.admin });
  }
});

// Página principal con productos
app.get('/', async (req, res) => {
  const query = 'SELECT * FROM productos';
  try {
    const products = await sql(query);
    res.render('index', { title: 'Página Principal', user: req.session.user, productos: products });
  } catch (error) {
    console.error('Error al obtener productos:', error);
    res.render('index', { title: 'Página Principal', user: req.session.user, productos: [] });
  }
});

// Agrega el producto al carrito o a la tabla de compras 
app.get('/carrito', async (req, res) => {
  // Verificar si el usuario está autenticado
  if (!req.session.user) {
    return res.redirect('/login'); // Redirigir al usuario a la página de login si no está autenticado
  }

  const userId = req.session.user.id;

  try {
    // Obtener productos en el carrito, incluyendo la cantidad y el total a pagar
    const query = `
      SELECT p.id AS producto_id, p.nombre, c.precio, p.imagen, COUNT(c.producto_id) AS cantidad
      FROM compras c
      JOIN productos p ON c.producto_id = p.id
      WHERE c.user_id = $1
      GROUP BY p.id, c.precio
    `;

    const productosResult = await sql(query, [userId]);

    // Calcula el total a pagar
    const total = productosResult.reduce((acc, producto) => acc + (producto.precio * producto.cantidad), 0);

    // Renderizar la vista del carrito con los productos y el total
    res.render('carrito', {
      productos: productosResult,
      total: total,
      user: req.session.user  // Pasar el usuario a la vista
    });
  } catch (error) {
    console.error('Error al obtener el carrito:', error);
    res.status(500).json({ success: false, message: 'Error al cargar el carrito.', error: error.message });
  }
});

// Intento de eliminación del producto del carrito 
app.post('/eliminar-producto', async (req, res) => {
  const { producto_id } = req.body;
  const user_id = req.session.user ? req.session.user.id : null; // Verificar si la sesión existe

  console.log('Producto ID:', producto_id);
  console.log('User ID:', user_id);

  // Verificación de que los IDs no estén vacíos
  if (!producto_id || !user_id) {
      return res.status(400).json({ success: false, message: 'El producto ID o el user ID están vacíos.' });
  }

  try {
      const existingProductQuery = 'SELECT * FROM compras WHERE producto_id = $1 AND user_id = $2';
      const existingProduct = await sql(existingProductQuery, [producto_id, user_id]);

      if (existingProduct.length === 0) {
          return res.status(404).json({ success: false, message: 'El producto no existe en el carrito.' });
      }

      // Eliminar el producto de la tabla compras
      await sql('DELETE FROM compras WHERE producto_id = $1 AND user_id = $2', [producto_id, user_id]);

      // Responder con éxito y un mensaje de confirmación
      return res.status(200).json({ success: true, message: 'Producto eliminado correctamente.' });
      
  } catch (error) {
      console.error('Error al eliminar el producto:', error);
      return res.status(500).json({ success: false, message: 'Error al eliminar el producto.' });
  }
});

// Agregar producto al carrito
app.post('/carrito', async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ success: false, message: 'Debes iniciar sesión para agregar productos al carrito.' });
  }

  const { user_id, producto_id, precio } = req.body;

  // Actualiza la consulta para usar 'id_compra' en lugar de 'id'
  const query = 'INSERT INTO compras (user_id, producto_id, precio) VALUES ($1, $2, $3) RETURNING id_compra'; // Cambia a id_compra

  try {
    const result = await sql(query, [user_id, producto_id, precio]);
    const id_compra = result[0].id_compra; // Asegúrate de acceder al nombre correcto de la columna

    res.status(200).json({ success: true, message: 'Producto agregado al carrito', id_compra: id_compra });
  } catch (error) {
    console.error('Error al agregar producto al carrito:', error);
    res.status(500).json({ success: false, message: 'Error al realizar la compra.', error: error.message });
  }
});

// esto es la parte de moneyy 
app.get('/wallet', async (req, res) => {
  // Asegúrate de que el usuario esté autenticado
  if (!req.session.user) {
    return res.redirect('/login'); // Redirigir a la página de login si no está autenticado
  }

  const userId = req.session.user.id; // Obtener el ID del usuario desde la sesión

  try {
    // Consulta para obtener el saldo del usuario
    const query = 'SELECT wallet FROM users WHERE id = $1';
    const result = await sql(query, [userId]);

    if (result.length > 0) {
      const wallet = result[0].wallet; // Obtener el saldo
      // Renderizar la vista de wallet y pasar el saldo
      res.render('wallet', {
        user: req.session.user, // Pasar el objeto de usuario
        wallet: wallet // Pasar el saldo a la vista
      });
    } else {
      res.status(404).json({ success: false, message: 'Usuario no encontrado.' });
    }
  } catch (error) {
    console.error('Error al obtener el saldo:', error);
    res.status(500).json({ success: false, message: 'Error al cargar el saldo.' });
  }
});

// esto pa recargar ,, mas que nada lo agrego para ver la funcion de pagar , que funcione bien 

app.post('/recargar', async (req, res) => {
  // Asegúrate de que el usuario esté autenticado
  if (!req.session.user) {
    return res.redirect('/login'); // Redirigir a la página de login si no está autenticado
  }

  const userId = req.session.user.id; // Obtener el ID del usuario desde la sesión
  const { monto } = req.body; // Obtener el monto del formulario

  if (!monto || monto <= 0) {
    return res.status(400).json({ success: false, message: 'El monto debe ser mayor que cero.' });
  }

  try {
    // Consulta para actualizar el saldo del usuario
    const query = 'UPDATE users SET wallet = wallet + $1 WHERE id = $2';
    await sql(query, [monto, userId]);

    // Redirigir a la página de wallet después de la recarga
    res.redirect('/wallet');
  } catch (error) {
    console.error('Error al recargar el saldo:', error);
    res.status(500).json({ success: false, message: 'Error al recargar el saldo.' });
  }
});

// esto pa pagar 
app.post('/pagar', async (req, res) => {
  console.log('Iniciando proceso de pago...');

  if (!req.session.user) {
    console.log('Usuario no autenticado');
    return res.status(401).json({ success: false, message: 'Debes iniciar sesión para realizar un pago.' });
  }

  const userId = req.session.user.id;
  console.log('Usuario ID:', userId);

  try {
    const productos = req.body.productos; // Obtener los productos del cuerpo de la solicitud
    const total = productos.reduce((acc, producto) => acc + (producto.precio * producto.cantidad), 0);
    console.log('Total calculado:', total);

    // Obtener el saldo del usuario
    const walletQuery = 'SELECT wallet FROM users WHERE id = $1';
    const walletResult = await sql(walletQuery, [userId]);
    const wallet = walletResult[0].wallet;
    console.log('Saldo del usuario:', wallet);

    if (wallet < total) {
      console.log('Saldo insuficiente');
      return res.status(400).json({ success: false, message: 'Saldo insuficiente para realizar el pago.' });
    }

    const newBalance = wallet - total;
    await sql('UPDATE users SET wallet = $1 WHERE id = $2', [newBalance, userId]);
    console.log('Nuevo saldo:', newBalance);

    // Obtener el nombre del usuario
    const userQuery = 'SELECT name FROM users WHERE id = $1';
    const userResult = await sql(userQuery, [userId]);
    const userName = userResult[0].name;

    // Registrar cada producto en la tabla de ventas ( que servira para historial )
    for (const producto of productos) {
      const nombreProducto = producto.nombre_producto;

      // usando producto_id utilizando el nombre del producto
      const productQuery = 'SELECT id FROM productos WHERE nombre = $1';
      const productResult = await sql(productQuery, [nombreProducto]);
      const productoId = productResult[0].id;

      
      const fecha = new Date().toISOString();

      // Insertar en la tabla de ventas
      await sql(`
        INSERT INTO ventas (user_id, producto_id, total, fecha, name, imagen_producto, nombre_producto)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
      `, [userId, productoId, producto.precio * producto.cantidad, fecha, userName, producto.imagen_producto, nombreProducto]);
    }

    await sql('DELETE FROM compras WHERE user_id = $1', [userId]);
    console.log('Productos eliminados del carrito.');

    res.status(200).json({ success: true, message: 'Pago realizado con éxito.', newBalance: newBalance });
  } catch (error) {
    console.error('Error al procesar el pago:', error);
    res.status(500).json({ success: false, message: 'Error al procesar el pago.' });
  }
});

// Ruta para mostrar el historial de compras
app.get('/historial', async (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }

  const userId = req.session.user.id;

  try {
    const query = `
      SELECT v.id AS id_venta, p.nombre AS producto, v.total AS precio, v.fecha AS fecha_compra
      FROM ventas v
      JOIN productos p ON v.producto_id = p.id
      WHERE v.user_id = $1
      ORDER BY v.fecha DESC
    `;

    const historialResult = await sql(query, [userId]);

    // Renderizar la vista del historial de compras
    res.render('historial', {
      title: 'Historial de Compras',
      user: req.session.user,
      ventas: historialResult // Pasa directamente el resultado
    });
  } catch (error) {
    console.error('Error al obtener el historial de compras:', error);
    res.status(500).send('Error en el servidor.');
  }
});




app.get('/descripcion/:id', async (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }

  const productoId = req.params.id;

  try {
    const query = `
      SELECT id, nombre, precio, imagen, descripcion 
      FROM productos 
      WHERE id = $1
    `;

    const productosResult = await sql(query, [productoId]);

    // Verifica el resultado
    console.log('Resultado de la consulta:', productosResult);

    if (productosResult.length === 0) {
      return res.status(404).send('Producto no encontrado');
    }

    const producto = productosResult[0];

    // Renderiza la vista de descripción
    res.render('descripcion', {
      producto: producto,
      user: req.session.user
    });
  } catch (error) {
    console.error('Error al obtener la descripción:', error);
    res.status(500).json({ success: false, message: 'Error al cargar la descripción.', error: error.message });
  }
});

app.post('/agregar-al-carro', async (req, res) => {
  const { user_id, producto_id, precio, fecha } = req.body;

  // Verificar que los datos estén disponibles
  if (!user_id || !producto_id || !precio) {
    return res.status(400).json({ success: false, message: 'Faltan datos para agregar al carrito.' });
  }

  try {
    // Verificar si el producto ya está en el carrito
    const existingProductQuery = 'SELECT * FROM compras WHERE user_id = $1 AND producto_id = $2';
    const existingProduct = await sql(existingProductQuery, [user_id, producto_id]);

    if (existingProduct.length > 0) {
      // Si el producto ya está en el carrito, puedes optar por actualizar la cantidad o enviar un mensaje
      return res.status(400).json({ success: false, message: 'El producto ya está en el carrito.' });
    }

    // Insertar el producto en la tabla compras
    const insertQuery = `
      INSERT INTO compras (user_id, producto_id, precio, fecha) 
      VALUES ($1, $2, $3, $4)
    `;
    await sql(insertQuery, [user_id, producto_id, precio, fecha]);

    // Responder con éxito
    res.json({ success: true, message: 'Producto agregado al carrito con éxito.' });
  } catch (error) {
    console.error('Error al agregar el producto al carrito:', error);
    res.status(500).json({ success: false, message: 'Error al agregar el producto al carrito.' });
  }
});



/////////////// Iniciar el servidor /////////////

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor ejecutándose en http://localhost:${PORT}`);
});
