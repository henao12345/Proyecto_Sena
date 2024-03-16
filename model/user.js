const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const saltRounds = 10;

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'trainer', 'user'], default: 'user' }
});

userSchema.pre('save', async function(next) {
    try {
        if (this.isNew || this.isModified('password')) {
            const hashedPassword = await bcrypt.hash(this.password, saltRounds);
            this.password = hashedPassword;
        }
        next();
    } catch (error) {
        next(error);
    }
});

userSchema.methods.isCorrectPassword = async function(password, callback) {
    try {
        const result = await bcrypt.compare(password, this.password);
        callback(null, result);
    } catch (error) {
        callback(error);
    }
};

const User = mongoose.model('User', userSchema);

module.exports = User;
