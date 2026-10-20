import mongoose from "mongoose";
import type { NextRequest } from "next/server";
import dbConnect from "@/lib/db";

type RateLimitDocument = mongoose.Document & {
	key: string;
	hits: Date[];
	expiresAt: Date;
	lastRequestAllowed: boolean;
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

type RateLimitCounter = Pick<
	RateLimitDocument,
	"hits" | "lastRequestAllowed"
>;

const rateLimitSchema = new mongoose.Schema<RateLimitDocument>(
	{
		key: { type: String, required: true, unique: true },
		hits: { type: [Date], required: true, default: [] },
		expiresAt: { type: Date, required: true, expires: 0 },
		lastRequestAllowed: { type: Boolean, required: true, default: false },
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
	const realIp = request.headers.get("x-real-ip")?.trim();
	if (realIp) {
		return realIp;
	}

	const forwardedFor = request.headers.get("x-forwarded-for");
	const forwardedIps = forwardedFor
		?.split(",")
		.map((ip) => ip.trim())
		.filter(Boolean);

	// Our ingress appends the source address to X-Forwarded-For, so the
	// rightmost address is the one supplied by the trusted proxy.
	return forwardedIps?.at(-1) || "unknown";
}

function validatePolicy(policy: RateLimitPolicy) {
	if (!Number.isInteger(policy.limit) || policy.limit <= 0) {
		throw new Error("Rate-limit policy limit must be a positive integer");
	}

	if (!Number.isFinite(policy.windowMs) || policy.windowMs <= 0) {
		throw new Error("Rate-limit policy windowMs must be a positive number");
	}
}

export async function checkRateLimit(
	request: NextRequest,
	policy: RateLimitPolicy,
): Promise<RateLimitResult> {
	validatePolicy(policy);

	const now = new Date();
	const cutoff = new Date(now.getTime() - policy.windowMs);
	const key = `${policy.name}:${getClientIp(request)}`;

	await dbConnect();

	const activeHits = {
		$filter: {
			input: { $ifNull: ["$hits", []] },
			as: "hit",
			cond: { $gt: ["$$hit", cutoff] },
		},
	};

	// A pipeline update makes pruning, checking, and recording a hit one atomic
	// operation. Keeping only allowed hits bounds the document at policy.limit.
	const update = [
		{
			$set: {
				hits: {
					$let: {
						vars: { activeHits },
						in: {
							$cond: [
								{ $lt: [{ $size: "$$activeHits" }, policy.limit] },
								{ $concatArrays: ["$$activeHits", [now]] },
								"$$activeHits",
							],
						},
					},
				},
				lastRequestAllowed: {
					$let: {
						vars: { activeHits },
						in: { $lt: [{ $size: "$$activeHits" }, policy.limit] },
					},
				},
				// TTL cleanup is deliberately not used for enforcement: Mongo's TTL
				// monitor is asynchronous, while the pipeline above is authoritative.
				expiresAt: new Date(now.getTime() + policy.windowMs),
			},
		},
	];

	const counter = (await RateLimit.findOneAndUpdate(
		{ key },
		update,
		{ new: true, upsert: true },
	)
		.lean()
		.catch(async (error: unknown) => {
			// Two simultaneous requests for a new key can race to insert. The
			// unique index lets one win; apply the other request to that document.
			if (
				typeof error === "object" &&
				error !== null &&
				"code" in error &&
				error.code === 11000
			) {
				return RateLimit.findOneAndUpdate(
					{ key },
					update,
					{ new: true },
				).lean();
			}

			throw error;
		})) as unknown as RateLimitCounter | null;

	if (!counter) {
		throw new Error("Could not create the rate-limit counter");
	}

	const oldestActiveHit = counter.hits[0];
	const reset = oldestActiveHit
		? oldestActiveHit.getTime() + policy.windowMs
		: now.getTime() + policy.windowMs;

	return {
		success: counter.lastRequestAllowed,
		limit: policy.limit,
		remaining: Math.max(0, policy.limit - counter.hits.length),
		reset,
	};
}
