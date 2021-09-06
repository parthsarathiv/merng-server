const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const { UserInputError } = require('apollo-server')

const { SECRET_KEY } = require('../../config')
const User = require('../../models/User')
const { validateRegisterInput, validateLoginInput } = require('../../utils/validators')

const generateToken = (user) => jwt.sign({
    id: user.id,
    email: user.email,
    username: user.username,
}, SECRET_KEY, { expiresIn: '1h'})

module.exports = {
    Mutation: {
        async login(_, { username, password }){
            const { errors, valid } = validateLoginInput(username, password)
            const user = await User.findOne({ username })

            if(!valid){
                throw new UserInputError('Errors', { errors })
            }

            if(!user) {
                errors.general = 'User not found!'

                throw new UserInputError ('User not found!', { errors })
            }

            const match = await bcrypt.compare(password, user.password)
            
            if(!match) {
                errors.general = 'Wrong credentials!'

                throw new UserInputError ('Wrong credentials', { errors })
            }

            const token = generateToken(user)

            return {
                email: user.email,
                username: user.username,
                createdAt: user.createdAt,
                id: user._id,
                token
            }
        },
        async register(_, { registerInput: { username, email, password, confirmPassword } }){
            //  Validate user data
            const {errors, valid} = validateRegisterInput(username, email, password, confirmPassword)
            if(!valid){
                throw new UserInputError('Erros', { errors })
            }
            //  make sure user doesent exit
            const user = await User.findOne( { username } )
            if(user){
                throw new UserInputError('Username is taken', {
                    errors :{
                        username: 'This username is taken'
                    }
                })
            }
            // Hash the password and creat an auth token
            password = await bcrypt.hash(password, 12)

            const newUser = new User({
                email,
                username,
                password,
                createdAt: new Date().toISOString()
            })

            const res = await newUser.save()

            const token = generateToken(res)

            // const token = "test"

            //console.log('>>> ', ...res, res._id, token)

            return {
                email: res.email,
                username: res.username,
                createdAt: res.createdAt,
                id: res._id,
                token
            }
        }
    }
}
