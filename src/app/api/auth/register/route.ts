import { type NextRequest, NextResponse } from "next/server";
import { generateToken } from "@/lib/auth/utils";
import dbConnect from "@/lib/db";
import User from "@/lib/models/user";
import { checkRateLimit, registerRateLimit } from "@/lib/rateLimit";

export async function POST(request: NextRequest) {
	try {
		const rateLimit = await checkRateLimit(request, registerRateLimit);
		if (!rateLimit.success) {
			const retryAfter = Math.ceil((rateLimit.reset - Date.now()) / 1000);
			return NextResponse.json(
				{ error: "Too many registration attempts. Please try again later." },
				{
					status: 429,
					headers: {
						"RateLimit-Limit": String(rateLimit.limit),
						"RateLimit-Remaining": "0",
						"RateLimit-Reset": String(Math.ceil(rateLimit.reset / 1000)),
						"Retry-After": String(retryAfter),
					},
				},
			);
		}

		await dbConnect();
		const body = await request.json();
		const { name, email, password } = body;

		// Validate required fields
		if (!name || !email || !password) {
			return NextResponse.json(
				{ error: "Please provide all required fields" },
				{ status: 400 },
			);
		}

		// Validate email format
		const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
		if (!emailRegex.test(email)) {
			return NextResponse.json(
				{ error: "Please provide a valid email address" },
				{ status: 400 },
			);
		}

		// Validate password length
		if (password.length < 8) {
			return NextResponse.json(
				{ error: "Password must be at least 8 characters long" },
				{ status: 400 },
			);
		}

		// Check if user already exists
		const userExists = await User.findOne({ email });
		if (userExists) {
			return NextResponse.json(
				{ error: "User already exists" },
				{ status: 400 },
			);
		}

		// Create user
		const user = await User.create({
			name,
			email,
			password,
		});

		// Generate token
		const token = await generateToken({
			userId: user._id.toString(),
			role: user.role,
		});

		const response = NextResponse.json({
			user: {
				id: user._id,
				name: user.name,
				email: user.email,
				role: user.role,
			},
			token,
		});

		// Set cookie
		response.cookies.set({
			name: "token",
			value: token,
			httpOnly: true,
			secure: process.env.NODE_ENV === "production",
			sameSite: "strict",
			path: "/",
		});

		return response;
	} catch (error: any) {
		return NextResponse.json(
			{ error: error.message || "Something went wrong" },
			{ status: 500 },
		);
	}
}
