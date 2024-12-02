const Hapi = require('@hapi/hapi');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
require('dotenv').config();

const prisma = new PrismaClient();

const init = async () => {
    const server = Hapi.server({
        port: process.env.PORT || 5000,
        host: '0.0.0.0',
        routes: {
            cors: {
                origin: ['*'], // Izinkan semua origin
            },
        },
    });
    
    // Middleware untuk validasi akses
    const accessValidation = async (request, h) => {
        const authorization = request.headers.authorization;

        if (!authorization) {
            return h.response({ message: 'Token diperlukan' }).code(401).takeover();
        }

        const token = authorization.split(' ')[1];
        const secret = process.env.JWT_SECRET;

        try {
            const jwtDecode = jwt.verify(token, secret);
            request.userData = jwtDecode; // Simpan data pengguna di `request`
        } catch (error) {
            return h.response({ message: 'Unauthorized' }).code(401).takeover();
        }
        return h.continue;
    };

    // Register user
    server.route({
        method: 'POST',
        path: '/register',
        handler: async (request, h) => {
            try {
                const { name, email, password } = request.payload;

                const hashedPassword = await bcrypt.hash(password, 10);
                const result = await prisma.users.create({
                    data: { name, email, password: hashedPassword },
                });

                return h.response({ message: 'User created', data: result }).code(201);
            } catch (error) {
                return h
                    .response({ message: 'Internal server error', error: error.message })
                    .code(500);
            }
        },
    });

    // Login user
    server.route({
        method: 'POST',
        path: '/login',
        handler: async (request, h) => {
            try {
                const { email, password } = request.payload;

                const user = await prisma.users.findUnique({ where: { email } });

                if (!user) {
                    return h.response({ message: 'User not found' }).code(404);
                }

                const isPasswordValid = await bcrypt.compare(password, user.password);

                if (isPasswordValid) {
                    const payload = { id: user.id, name: user.name, address: user.address };
                    const secret = process.env.JWT_SECRET;
                    const expiresIn = 60 * 60 * 1; // 1 hour

                    const token = jwt.sign(payload, secret, { expiresIn });

                    return h.response({ data: payload, token }).code(200);
                } else {
                    return h.response({ message: 'Wrong password' }).code(403);
                }
            } catch (error) {
                return h
                    .response({ message: 'Internal server error', error: error.message })
                    .code(500);
            }
        },
    });

    // Read all users
    server.route({
        method: 'GET',
        path: '/users',
        options: {
            pre: [{ method: accessValidation }],
        },
        handler: async (request, h) => {
            try {
                const result = await prisma.users.findMany({
                    select: { id: true, name: true, email: true, address: true },
                });

                return h.response({ data: result, message: 'User list' }).code(200);
            } catch (error) {
                return h
                    .response({ message: 'Internal server error', error: error.message })
                    .code(500);
            }
        },
    });

    // Delete user
    server.route({
        method: 'DELETE',
        path: '/users/{id}',
        options: {
            pre: [{ method: accessValidation }],
        },
        handler: async (request, h) => {
            try {
                const { id } = request.params;

                await prisma.users.delete({ where: { id: Number(id) } });

                return h.response({ message: `User ${id} deleted` }).code(200);
            } catch (error) {
                return h
                    .response({ message: 'Internal server error', error: error.message })
                    .code(500);
            }
        },
    });

    await server.start();
    console.log(`Server running on ${server.info.uri}`);
};

process.on('unhandledRejection', (err) => {
    console.log(err);
    process.exit(1);
});

init();
