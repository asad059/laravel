<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Support\Facades\Mail;
use Carbon\Carbon;

class AuthController extends Controller
{
    /**
     * @api {POST} /api/login/ 1. Login Request
     * @apiName Login
     * @apiGroup Auth
     * 
     * @apiPermission Registered users are allowed to login.
     * 
     * @apiDescription This API is used to login the user. Confirm the login credentials and return user record.
     *
     * @apiBody {string} email Email ID.
     * @apiBody {string} password Password.
     *
     * @apiSuccess {String} message Success Login Message.
     * @apiSuccess {String} token Access token to access other API endpoints.
     * @apiSuccess {Object[]} data Logged-in user info.
     * 
     * @apiError {String} message User does not exist.
     * @apiError {String} data Empty.
     * 
     */
    public function login(Request $request)
    {
        // Validate Fileds
        $login_fields = $request->validate([
            'email' => 'required|string|max:255',
            'password' => 'required|string|max:255'
        ]);

        $user = User::where('email', $login_fields['email'])->first();
        // Check if user exists with the provided email id
        if(!$user)
        {
            return response([
                'message' => 'User does not exists.', 
                'data' => ''
            ], 401); 
        }

        // Check if the correct password is provided
        if(!Hash::check($login_fields['password'], $user->password))
        {
            return response([
                'message' => 'Password is not correct.', 
                'data' => ''
            ], 401);
        }

        // generate token for authentication
        $token = $user->createToken('sample-app-'.$user->email)->plainTextToken;

        return response([
            'message' => 'User Logged In Successfully!', 
            'data' => $user, 
            'token' => $token
        ], 200);
    
    }

    /**
     * @api {GET} /api/logout/ 2. Logout Request
     * @apiName Logout
     * @apiGroup Auth
     * 
     * @apiPermission User should be logged in.
     *
     * @apiHeader {string} Authorization Bearer "Token"
     *
     * @apiSuccess {String} message Success Logout Message.
     * @apiSuccess {string} data Empty.
     * 
     * @apiError {String} message Unauthenticated.
     * 
     */
    public function logout()
    {
        auth()->user()->tokens()->delete();

        return response(['message' => 'Logged Out Successfully.', 'data' => ''], 200);
    }

    /**
     * @api {POST} /api/register/ 3. Register Request
     * @apiName Register
     * @apiGroup Auth
     * 
     * @apiDescription This API is used to register a user. Confirm the credentials and return user record, show error if user already exists.
     *
     * @apiBody {string} name Name.
     * @apiBody {string} email Email ID.
     * @apiBody {string} password Password.
     * @apiBody {string} password_confirmation Confirm/Re-type Password.
     *
     * @apiSuccess {String} message Success Signup/register Message.
     * @apiSuccess {String} token Access token to access other API endpoints.
     * @apiSuccess {Object[]} data Signed-up/Register user info.
     * 
     * @apiError {String} message Any error message (Email already exists or Duplicate company name etc).
     * @apiError {object[]} errors Contains error messages.
     * @apiError {object[]} errors.email Email already exists message.
     * @apiError {object[]} errors.company Company with same name already exists message.
     * 
     */
    public function register(Request $request)
    {
        $role = 'admin';
        $invitation = NULL;

        $request->validate([
            'email' => 'required|string|max:255|unique:users,email',
            'name' => 'required|string|max:255', 
            'password' => 'required|min:8|confirmed|max:255'
        ],[
            'email.required' => 'Email is required',
            'email.unique' => 'Email id is already in use.',
            'name.required' => 'Name is required',
            'password.required' => 'Password field should not be empty',
            'password.min' => 'Password should be atleast 8 characters long.',
            'password.confirmed' => 'Password and Confirm Password should be same!'
        ]);

        // create user
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        // return the created object
        return response([
            'message' => 'User Signed up Successfully!', 
            'data' => $user
        ], 201);
    }

    /**
     * @api {POST} /api/forget-password/ 5. Forget Password Request
     * @apiName Forget Password
     * @apiGroup Auth
     * 
     * @apiPermission User should be Registered with the provided email ID.
     * 
     * @apiDescription This API is used when a user forgets the password and wants to reset it. A confirmation email with reset password link will be send to the provided email id.
     *
     * @apiBody {string} email Email ID.
     *
     * @apiSuccess {String} message Success Message (an email send with the reset password link).
     * @apiSuccess {String} data
     * 
     * @apiError {String} message Any error message (Provided email Id not exists, reset link already sent etc).
     * @apiError {String} data
     * 
     */
    public function forgetPassword(Request $request)
    {
        $request->validate([
            'email' => 'required|email'
        ],[
            'email.required' => 'Email Field is Required'
        ]);

        $status = Password::sendResetLink(
            $request->only('email')
        );

        if($status == Password::RESET_LINK_SENT)
        {
            return response([
                'message' => 'An Email send to your email id with password reset link!', 
                'data' => ''
            ], 200);
        } 
        else if($status == Password::RESET_THROTTLED)
        {
            return response([
                'message' => 'An Email is already send to your email id with password reset link. Kindly check you inbox.', 
                'data' => ''
            ], 200);
        }
        else
        {
            return response([
                'message' => 'Provided email ID does not exists in our records. kindly try with correct email ID.', 
                'data' => ''
            ], 200);
        }
    }

    /**
     * @api {POST} /api/reset-password/ 6. Reset Password Request
     * @apiName Reset Password
     * @apiGroup Auth
     * 
     * @apiPermission User should be Registered with the provided email ID.
     * 
     * @apiDescription This API is used when a user forgets the password and wants to reset it. A confirmation email with reset password link will be send to the provided email id.
     *
     * @apiBody {string} token Token which is was sent in the reset passwrod email with the reset link.
     * @apiBody {String} email Email ID
     * @apiBody {String} password New Password
     * @apiBody {String} password_confirmation Confirm/Re-type New Password
     * 
     * @apiSuccess {String} message Success Message (Password reset successfully).
     * @apiSuccess {String} data
     * 
     * @apiError {String} message Any error message (Password reset token expires, Passowrd cannot be reset etc).
     * @apiError {String} data
     * 
     */
    public function resetPassword(Request $request)
    {
        $request->validate([
            'token' => 'required',
            'email' => 'required|email',
            'password' => 'required|min:8|confirmed',
        ],[
            'token.required' => 'Reset password token is required!',
            'email.required' => 'A Valid Email is Required!',
            'password.required' => 'Password is Required!',
            'password.confirmed' => 'Password and Confirm Password should be same!'
        ]);
     
        $status = Password::reset(
            $request->only('email', 'password', 'password_confirmation', 'token'),
            function ($user, $password) {
                $user->forceFill([
                    'password' => Hash::make($password)
                ]);
     
                $user->save();
     
                event(new PasswordReset($user));
            }
        );

        if($status == Password::PASSWORD_RESET)
        {
            return response([
                'message' => 'Password Reset Successfully!', 
                'data' => ''
            ], 200);
        }
        else if ($status == Password::INVALID_TOKEN)
        {
            return response([
                'message' => 'Password Reset Token is Expired. Try Reset Password again.', 
                'data' => ''
            ], 422);
        }
        else
        {
            return response([
                'message' => 'Password cannot be reset!', 
                'data' => ''
            ], 422);
        }

    }

    /**
     * @api {HEAD} /sanctum/csrf-cookie/ 7. Set Sanctum CSRF Cookie
     * @apiName Set Sanctum CSRF Cookie Header
     * @apiGroup Auth
     * 
     * @apiDescription This API is used to set Sanctum XSRF-TOKEN Cookie to avoid CORS error. This API will show 204 status (no content).
     * 
     */

}