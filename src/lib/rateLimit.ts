import mongoose from "mongoose";
import type { NextRequest } from "next/server";
import dbConnect from "@/lib/db";

type RateLimitDocument = mongoose.Document & {
	key: string;
	count: number;
	expiresAt: Date;
};

export type RateLimitPolicy = {
	name: string;
	limit: number;
	windowMs: number;
};

type RateLimitResult = {
	success: boolean;
	limit: number;
	remaining: number;
	reset: number;
};

const rateLimitSchema = new mongoose.Schema<RateLimitDocument>(
	{
		key: { type: String, required: true, unique: true },
		count: { type: Number, required: true, default: 0 },
		expiresAt: { type: Date, required: true, expires: 0 },
	},
	{ versionKey: false },
);

const RateLimit =
	mongoose.models.RateLimit ||
	mongoose.model<RateLimitDocument>("RateLimit", rateLimitSchema);

export const loginRateLimit: RateLimitPolicy = {
	name: "login",
	limit: 5,
	windowMs: 15 * 60 * 1000,
};

export const registerRateLimit: RateLimitPolicy = {
	name: "register",
	limit: 3,
	windowMs: 60 * 60 * 1000,
};

function getClientIp(request: NextRequest): string {
	const forwardedFor = request.headers.get("x-forwarded-for");

	return (
		forwardedFor?.split(",")[0]?.trim() ||
		request.headers.get("x-real-ip") ||
		"unknown"
	);
}

export async function checkRateLimit(
	request: NextRequest,
	policy: RateLimitPolicy,
): Promise<RateLimitResult> {
	const now = Date.now();
	const bucket = Math.floor(now / policy.windowMs);
	const reset = (bucket + 1) * policy.windowMs;
	const key = `${policy.name}:${getClientIp(request)}:${bucket}`;

	await dbConnect();

	const counter = await RateLimit.findOneAndUpdate(
		{ key },
		{
			$inc: { count: 1 },
			$setOnInsert: { expiresAt: new Date(reset + policy.windowMs) },
		},
		{ new: true, upsert: true },
	).lean();

	if (!counter) {
		throw new Error("Could not create the rate-limit counter");
	}

	return {
		success: counter.count <= policy.limit,
		limit: policy.limit,
		remaining: Math.max(0, policy.limit - counter.count),
		reset,
	};
}
