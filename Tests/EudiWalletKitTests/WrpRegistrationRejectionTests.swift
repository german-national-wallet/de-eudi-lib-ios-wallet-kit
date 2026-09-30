import Testing
import Foundation
import OpenID4VP
import MdocDataModel18013
@testable import EudiWalletKit

/// Covers the classification a wallet needs in order to refuse a presentation request on
/// registration-certificate grounds, which wallet-kit itself never does.
struct WrpRegistrationRejectionTests {

	// MARK: - classifying the thrown error

	/// The library reports the reason only as free text, so these are the exact messages
	/// `RequestAuthenticator.validateRegistrationCertificateIfNeeded` raises.
	@Test(arguments: [
		"WRPRC policy is configured but verifier_info is missing",
		"WRPRC policy is configured but no WRPRC found in verifier_info",
		"WRPRC policy is configured but client does not have an authentication certificate (WRPAC)",
		"Multiple WRPRCs found in verifier_info. Per CIR 2024/2082, only one WRPRC is allowed."
	])
	func classifiesEveryRegistrationCertificateFailure(message: String) {
		let error = makeResolutionError(message: message)
		#expect(error.wrpRegistrationRejection == .certificateMissing)
	}

	@Test func ignoresUnrelatedResolutionFailures() {
		let error = makeResolutionError(message: "Invalid response type")
		#expect(error.wrpRegistrationRejection == nil)
	}

	@Test func ignoresUnrelatedErrorCodes() {
		// Same message, but a code that cannot come from request resolution.
		let error = WalletError(
			description: "WRPRC policy is configured but verifier_info is missing",
			code: .noDocumentsAvailable
		)
		#expect(error.wrpRegistrationRejection == nil)
	}

	/// `.trustError` is used instead of `.invalidQueryResolution` whenever a reader-certificate
	/// validation message is present, so both codes have to be classified.
	@Test func classifiesUnderTrustErrorCodeToo() {
		let error = WalletError(
			description: "OpenID4VP request error: WRPRC policy is configured but verifier_info is missing",
			code: .trustError
		)
		#expect(error.wrpRegistrationRejection == .certificateMissing)
	}

	/// The reason may only be reachable through the wrapped library error.
	@Test func classifiesFromTheInnerErrorAlone() {
		let error = WalletError(
			description: "OpenID4VP request error",
			code: .invalidQueryResolution,
			innerError: ValidationError.validationError("WRPRC policy is configured but verifier_info is missing")
		)
		#expect(error.wrpRegistrationRejection == .certificateMissing)
	}

	// MARK: - finding over-asking among the warnings

	@Test func findsOverAskedClaimsAmongOtherViolations() {
		let overAsked = PresentationPolicyViolation(
			reason: .overAskedClaims(docType: "eu.europa.ec.eudi.pid.1", claims: nil),
			message: "not declared in the registration certificate policy"
		)
		let unrelated = PresentationPolicyViolation(reason: .statusMissing, message: "status missing")

		let violations = [unrelated, overAsked]
		#expect(violations.containsOverAskedClaims)
		#expect(violations.overAskedClaimViolations == [overAsked])
	}

	@Test func reportsNoOverAskingWhenOnlyOtherViolationsArePresent() {
		let violations = [
			PresentationPolicyViolation(reason: .expired, message: "expired"),
			PresentationPolicyViolation(reason: .trustError, message: "trust error")
		]
		#expect(violations.containsOverAskedClaims == false)
		#expect(violations.overAskedClaimViolations.isEmpty)
	}

	@Test func reportsNoOverAskingForNoViolations() {
		let violations: [PresentationPolicyViolation] = []
		#expect(violations.containsOverAskedClaims == false)
	}

	// MARK: - helpers

	/// Mirrors how `OpenId4VpService.receiveRequest` wraps an `.invalidResolution` outcome.
	private func makeResolutionError(message: String) -> WalletError {
		WalletError(
			description: "OpenID4VP request error: \(message)",
			code: .invalidQueryResolution,
			innerError: ValidationError.validationError(message)
		)
	}
}
