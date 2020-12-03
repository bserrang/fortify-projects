import { ArrayBufferConverter, ProtobufElement, ProtobufProperty } from "tsprotobuf";
import { CryptoActionProto } from "./crypto";
import { AlgorithmProto, CryptoKeyProto } from "./proto";

@ProtobufElement({})
export class DigestActionProto extends CryptoActionProto {

  public static INDEX = CryptoActionProto.INDEX;
  public static ACTION = "crypto/subtle/digest";

  @ProtobufProperty({ id: DigestActionProto.INDEX++, required: true, parser: AlgorithmProto })
  public algorithm: AlgorithmProto = new AlgorithmProto();

  @ProtobufProperty({ id: DigestActionProto.INDEX++, required: true, converter: ArrayBufferConverter })
  public data: ArrayBuffer = new ArrayBuffer(0);

}

@ProtobufElement({})
export class GenerateKeyActionProto extends CryptoActionProto {

  public static INDEX = CryptoActionProto.INDEX;
  public static ACTION = "crypto/subtle/generateKey";

  @ProtobufProperty({ id: GenerateKeyActionProto.INDEX++, type: "bytes", required: true, parser: AlgorithmProto })
  public algorithm: AlgorithmProto = new AlgorithmProto();

  @ProtobufProperty({ id: GenerateKeyActionProto.INDEX++, type: "bool", required: true })
  public extractable: boolean = false;

  @ProtobufProperty({ id: GenerateKeyActionProto.INDEX++, type: "string", repeated: true })
  public usage: string[] = [];

}

@ProtobufElement({})
export class SignActionProto extends CryptoActionProto {

  public static INDEX = CryptoActionProto.INDEX;
  public static ACTION = "crypto/subtle/sign";

  @ProtobufProperty({ id: SignActionProto.INDEX++, required: true, parser: AlgorithmProto })
  public algorithm: AlgorithmProto = new AlgorithmProto();

  @ProtobufProperty({ id: SignActionProto.INDEX++, required: true, parser: CryptoKeyProto })
  public key: CryptoKeyProto = new CryptoKeyProto();

  @ProtobufProperty({ id: SignActionProto.INDEX++, required: true, converter: ArrayBufferConverter })
  public data: ArrayBuffer = new ArrayBuffer(0);

}

@ProtobufElement({})
export class VerifyActionProto extends SignActionProto {

  public static INDEX = SignActionProto.INDEX;
  public static ACTION = "crypto/subtle/verify";

  @ProtobufProperty({ id: VerifyActionProto.INDEX++, required: true, converter: ArrayBufferConverter })
  public signature: ArrayBuffer = new ArrayBuffer(0);

}

@ProtobufElement({})
export class EncryptActionProto extends SignActionProto {

  public static INDEX = SignActionProto.INDEX;
  public static ACTION = "crypto/subtle/encrypt";

}

@ProtobufElement({})
export class DecryptActionProto extends SignActionProto {

  public static INDEX = SignActionProto.INDEX;
  public static ACTION = "crypto/subtle/decrypt";

}

@ProtobufElement({})
export class DeriveBitsActionProto extends CryptoActionProto {

  public static INDEX = CryptoActionProto.INDEX;
  public static ACTION = "crypto/subtle/deriveBits";

  @ProtobufProperty({ id: DeriveBitsActionProto.INDEX++, required: true, parser: AlgorithmProto })
  public algorithm: AlgorithmProto = new AlgorithmProto();

  @ProtobufProperty({ id: DeriveBitsActionProto.INDEX++, required: true, parser: CryptoKeyProto })
  public key: CryptoKeyProto = new CryptoKeyProto();

  @ProtobufProperty({ id: DeriveBitsActionProto.INDEX++, required: true, type: "uint32" })
  public length: number = 0;

}

@ProtobufElement({})
export class DeriveKeyActionProto extends CryptoActionProto {

  public static INDEX = CryptoActionProto.INDEX;
  public static ACTION = "crypto/subtle/deriveKey";

  @ProtobufProperty({ id: DeriveKeyActionProto.INDEX++, required: true, parser: AlgorithmProto })
  public algorithm: AlgorithmProto = new AlgorithmProto();

  @ProtobufProperty({ id: DeriveKeyActionProto.INDEX++, required: true, parser: CryptoKeyProto })
  public key: CryptoKeyProto = new CryptoKeyProto();

  @ProtobufProperty({ id: DeriveKeyActionProto.INDEX++, required: true, parser: AlgorithmProto })
  public derivedKeyType: AlgorithmProto = new AlgorithmProto();

  @ProtobufProperty({ id: DeriveKeyActionProto.INDEX++, type: "bool" })
  public extractable: boolean = false;

  @ProtobufProperty({ id: DeriveKeyActionProto.INDEX++, type: "string", repeated: true })
  public usage: string[] = [];

}

@ProtobufElement({})
export class UnwrapKeyActionProto extends CryptoActionProto {

  public static INDEX = CryptoActionProto.INDEX;
  public static ACTION = "crypto/subtle/unwrapKey";

  @ProtobufProperty({ id: UnwrapKeyActionProto.INDEX++, required: true, type: "string" })
  public format: string = "";

  @ProtobufProperty({ id: UnwrapKeyActionProto.INDEX++, required: true, converter: ArrayBufferConverter })
  public wrappedKey: ArrayBuffer = new ArrayBuffer(0);

  @ProtobufProperty({ id: UnwrapKeyActionProto.INDEX++, required: true, parser: CryptoKeyProto })
  public unwrappingKey: CryptoKeyProto = new CryptoKeyProto();

  @ProtobufProperty({ id: UnwrapKeyActionProto.INDEX++, required: true, parser: AlgorithmProto })
  public unwrapAlgorithm: AlgorithmProto = new AlgorithmProto();

  @ProtobufProperty({ id: UnwrapKeyActionProto.INDEX++, required: true, parser: AlgorithmProto })
  public unwrappedKeyAlgorithm: AlgorithmProto = new AlgorithmProto();

  @ProtobufProperty({ id: UnwrapKeyActionProto.INDEX++, type: "bool" })
  public extractable: boolean = false;

  @ProtobufProperty({ id: UnwrapKeyActionProto.INDEX++, type: "string", repeated: true })
  public keyUsage: string[] = [];

}

@ProtobufElement({})
export class WrapKeyActionProto extends CryptoActionProto {

  public static INDEX = CryptoActionProto.INDEX;
  public static ACTION = "crypto/subtle/wrapKey";

  @ProtobufProperty({ id: WrapKeyActionProto.INDEX++, required: true, type: "string" })
  public format: string = "";

  @ProtobufProperty({ id: WrapKeyActionProto.INDEX++, required: true, parser: CryptoKeyProto })
  public key: CryptoKeyProto = new CryptoKeyProto();

  @ProtobufProperty({ id: WrapKeyActionProto.INDEX++, required: true, parser: CryptoKeyProto })
  public wrappingKey: CryptoKeyProto = new CryptoKeyProto();

  @ProtobufProperty({ id: WrapKeyActionProto.INDEX++, required: true, parser: AlgorithmProto })
  public wrapAlgorithm: AlgorithmProto = new AlgorithmProto();

}

@ProtobufElement({})
export class ExportKeyActionProto extends CryptoActionProto {

  public static INDEX = CryptoActionProto.INDEX;
  public static ACTION = "crypto/subtle/exportKey";

  @ProtobufProperty({ id: ExportKeyActionProto.INDEX++, type: "string", required: true })
  public format: string = "";

  @ProtobufProperty({ id: ExportKeyActionProto.INDEX++, required: true, parser: CryptoKeyProto })
  public key: CryptoKeyProto = new CryptoKeyProto();

}

@ProtobufElement({})
export class ImportKeyActionProto extends CryptoActionProto {

  public static INDEX = CryptoActionProto.INDEX;
  public static ACTION = "crypto/subtle/importKey";

  @ProtobufProperty({ id: ImportKeyActionProto.INDEX++, type: "string", required: true })
  public format: string = "";

  @ProtobufProperty({ id: ImportKeyActionProto.INDEX++, required: true, converter: ArrayBufferConverter })
  public keyData: ArrayBuffer = new ArrayBuffer(0);

  @ProtobufProperty({ id: ImportKeyActionProto.INDEX++, required: true, parser: AlgorithmProto })
  public algorithm: AlgorithmProto = new AlgorithmProto();

  @ProtobufProperty({ id: ImportKeyActionProto.INDEX++, required: true, type: "bool" })
  public extractable: boolean = false;

  @ProtobufProperty({ id: ImportKeyActionProto.INDEX++, type: "string", repeated: true })
  public keyUsages: string[] = [];

}
