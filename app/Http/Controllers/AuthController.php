<?php

namespace App\Http\Controllers;
use Auth;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function __construct()
    {
            $this->middleware('auth:api', ['except'=>['login', 'register']]);

    }
    public function register(Request $request){
            $validator = Validator::make($request->all(),[
            'name' => ['required' ,'string', 'regex:/^[a-zA-Z ]*$/', 'max:255'],
            'email' => ['required','string', 'email:rfc,dns', 'max:255', 'unique:users'],
            'password' => ['required', 'string', 'min:8', 'regex:/[a-z]/', 'regex:/[A-Z]/', 'regex:/[0-9]/', 'regex:/[@$!%*#?&]/', 'confirmed'],
        ],
        [   
            'name.required'    => 'Please Provide Your Name.',
            'name.regex'    => 'Invalid Characters',
            'email.required'    => 'Please Provide Your Email Address',
            'email.unique'      => 'Sorry, This Email Address Is Already Used By Another User. Please Try With Different One, Thank You.',
            'email.email'      => 'Invaild Email!!!',
            'password.required' => 'Password needed',
            'password.min'      => 'Password should be more than 8 characters',
            'password.regex'      => 'Password should have an upper and lower case with at least one number and one special character ',
        ]
    );

        if($validator->fails()){
            return response()->json($validator->errors()->toJson(),400);
        }
      else{
        $user = User::create(array_merge(
            $validator->validated(),
            ['password'=>Hash::make($request->password)]
        ));
        return response()->json([
            'message'=>'User successfully registered',
            'user'=>$user
        ],201);
      }
    }
    

    public function login(Request $request){

        $validator = Validator::make($request->all(),[
            'email' => ['required','string', 'email:rfc,dns'],
            'password' => ['required', 'string', 'min:8', 'regex:/[a-z]/', 'regex:/[A-Z]/', 'regex:/[0-9]/', 'regex:/[@$!%*#?&]/'],
        ],
    );
    if($validator->fails()){
        return response()->json($validator->errors()->toJson(),422);
    }
    else{
        if(!$token=auth()->attempt($validator->validated())){
          return response()->json(['error'=>'Unauthorized', 401]);  
        }
    }
    return $this->createNewToken($token);
 }

        public function refresh()
        {
            /** @var Illuminate\Auth\AuthManager */
            $auth = auth();
            return $this->createNewToken($auth->refresh());
        }

    public function createNewToken($token){
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL()*60,  
            'user' => auth()->user() 
        ]);
 }

    public function profile(){
        return response()->json(auth()->user());
    }

    public function logout(){
        auth()->logout();
        return response()->json([
            'message'=>'User logged out',
        ]);
    }
}
