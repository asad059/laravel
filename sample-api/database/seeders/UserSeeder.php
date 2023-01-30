<?php

namespace Database\Seeders;

use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Support\Facades\Hash;
use App\Models\User;
use Illuminate\Database\Seeder;

class UserSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        User::updateOrCreate([
            'email' => 'super.admin@sample-app.com',
        ],[
            'name' => 'Super Admin',
            'email_verified_at' => now(),
            'password' => Hash::make('abcd1234'),
        ]);
        
        User::updateOrCreate([
            'email' => 'app.member@sample-app.com',
        ],[
            'name' => 'Application Member',
            'email_verified_at' => now(),
            'password' => Hash::make('abcd1234'),
        ]);
    }
}
