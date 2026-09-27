/** Types for build-time generated Ajv wire validators. No runtime schema eval. */
type Validator = ((document: unknown) => boolean) & { errors?: unknown[] | null };
export declare const validateEnvelope: Validator;
export declare const validateHandshakeAcceptPayload: Validator;
export declare const validateFirmQuoteRequest: Validator;
export declare const validateTermsOffer: Validator;
export declare const validateQuoteError: Validator;
export declare const validateContractTerms: Validator;
export declare const validateFundingBinding: Validator;
export declare const validateTermsAccept: Validator;
export declare const validateFundingBindingMessage: Validator;
export declare const validateAck: Validator;
export declare const validateObservation: Validator;
