import { describe, expect, it } from "vitest";
import {
  EMPTY_PLACEHOLDER,
  MAX_CHAT_MESSAGE_CODEPOINTS,
  MAX_DRAFT_DESCRIPTION_CODEPOINTS,
  countCodePoints,
  formatInteger,
  formatIsoTimestamp,
  formatMinorAmount,
  formatOrEmpty,
  formatPercent,
  formatUnixSeconds,
  isWithinCodePointLimit,
  truncateMiddle,
  validateChatMessage,
  validateDraftDescription,
} from "./format";

describe("Unicode code point counting and validation", () => {
  it("counts ASCII, CJK, and surrogate-pair emoji by Unicode code points", () => {
    expect(countCodePoints("")).toBe(0);
    expect(countCodePoints("hello")).toBe(5);
    expect(countCodePoints("采购一件P1")).toBe(6);
    // Single emoji uses 2 UTF-16 code units but 1 Unicode code point.
    expect("🚀".length).toBe(2);
    expect(countCodePoints("🚀")).toBe(1);
    expect(countCodePoints("采购🚀A1")).toBe(5);
  });

  it("enforces exact 4000-codepoint chat message boundary", () => {
    const exactEmoji = "🚀".repeat(MAX_CHAT_MESSAGE_CODEPOINTS);
    expect(exactEmoji.length).toBe(8000);
    expect(isWithinCodePointLimit(exactEmoji, MAX_CHAT_MESSAGE_CODEPOINTS)).toBe(
      true,
    );
    const okResult = validateChatMessage(`  ${exactEmoji}  `);
    expect(okResult.ok).toBe(true);
    if (okResult.ok) {
      expect(okResult.count).toBe(MAX_CHAT_MESSAGE_CODEPOINTS);
    }

    const overLimit = `${exactEmoji}a`;
    const failResult = validateChatMessage(overLimit);
    expect(failResult.ok).toBe(false);
    if (!failResult.ok) {
      expect(failResult.count).toBe(MAX_CHAT_MESSAGE_CODEPOINTS + 1);
    }

    expect(validateChatMessage("   ").ok).toBe(false);
  });

  it("enforces exact 512-codepoint draft description boundary", () => {
    const exact = "购".repeat(MAX_DRAFT_DESCRIPTION_CODEPOINTS);
    expect(validateDraftDescription(exact).ok).toBe(true);

    const exactWithEmoji = "📦".repeat(MAX_DRAFT_DESCRIPTION_CODEPOINTS);
    expect(exactWithEmoji.length).toBe(1024);
    expect(validateDraftDescription(exactWithEmoji).ok).toBe(true);

    const over = `${exactWithEmoji}1`;
    expect(validateDraftDescription(over).ok).toBe(false);
    expect(validateDraftDescription("").ok).toBe(false);
  });
});

describe("Currency, number, timestamp, and empty formatting", () => {
  it("formats minor amounts cleanly with currency symbol and tabular precision", () => {
    expect(formatMinorAmount(80000)).toBe("¥800.00");
    expect(formatMinorAmount(100000)).toBe("¥1,000.00");
    expect(formatMinorAmount(120000)).toBe("¥1,200.00");
    expect(formatMinorAmount(1234567)).toBe("¥12,345.67");
    expect(formatMinorAmount(0)).toBe("¥0.00");
    expect(formatMinorAmount(5)).toBe("¥0.05");
    expect(formatMinorAmount(-12345)).toBe("-¥123.45");
    expect(formatMinorAmount(120000, "USD")).toBe("USD 1,200.00");
  });

  it("renders null, undefined, and non-finite amounts as em-dash placeholder", () => {
    expect(formatMinorAmount(null)).toBe(EMPTY_PLACEHOLDER);
    expect(formatMinorAmount(undefined)).toBe(EMPTY_PLACEHOLDER);
    expect(formatMinorAmount(Number.NaN)).toBe(EMPTY_PLACEHOLDER);
    expect(formatMinorAmount(Number.POSITIVE_INFINITY)).toBe(EMPTY_PLACEHOLDER);
  });

  it("formats integers, percentages, empty values, and UTC timestamps", () => {
    expect(formatInteger(12345)).toBe("12,345");
    expect(formatInteger(null)).toBe(EMPTY_PLACEHOLDER);

    expect(formatPercent(0.1234)).toBe("12.3%");
    expect(formatPercent(undefined)).toBe(EMPTY_PLACEHOLDER);

    expect(formatOrEmpty("")).toBe(EMPTY_PLACEHOLDER);
    expect(formatOrEmpty("   ")).toBe(EMPTY_PLACEHOLDER);
    expect(formatOrEmpty(null)).toBe(EMPTY_PLACEHOLDER);
    expect(formatOrEmpty(0)).toBe("0");
    expect(formatOrEmpty("A")).toBe("A");

    expect(formatUnixSeconds(1700000000, { utc: true })).toBe(
      "2023-11-14 22:13:20 UTC",
    );
    expect(
      formatUnixSeconds(1700000000, { utc: true, includeSeconds: false }),
    ).toBe("2023-11-14 22:13 UTC");
    expect(formatUnixSeconds(0)).toBe(EMPTY_PLACEHOLDER);
    expect(formatUnixSeconds(null)).toBe(EMPTY_PLACEHOLDER);

    expect(
      formatIsoTimestamp("2026-11-26T05:30:15Z", { utc: true }),
    ).toBe("2026-11-26 05:30:15 UTC");
    expect(formatIsoTimestamp(null)).toBe(EMPTY_PLACEHOLDER);

    expect(truncateMiddle("short")).toBe("short");
    expect(
      truncateMiddle("sha256:0123456789abcdef0123456789abcdef", 10, 6),
    ).toBe("sha256:012…abcdef");
  });
});
