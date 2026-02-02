declare module "jsonwebtoken" {
	function decode(t: string, o: DecodeOptions): Jwt | JwtPayload | string | null
	function sign(p: object, k: string, o: SignOptions): string
	function verify(t: string, k: string, o: VerifyOptions): Jwt | JwtPayload | string
}
