
import { Component, Host, h, State, Prop } from '@stencil/core';
// import { } from '@webcrypto-local/client';
import { allImports } from '../../utils/all-imports.js';
// import {wcc} from  '../../utils/all-imports';


@Component({
  tag: 'fortify-sign',
  styleUrl: 'fortify-sign.css',
  shadow: true,
})
export class FortifySign {

  providerDefault;
  certificate;
  typeSign: HTMLInputElement;
  signBase;
  @State() signatureBase = '';
  @State() verificationBase;
  messageBase: HTMLTextAreaElement;
  @Prop() cnData;
  allReferences;




  componentDidLoad() {
    console.log(this.allReferences);
    this.messageBase.value = `<xml>
  <text>Demo</text>
</xml>`;
    this.main();
  }

  disconnectedCallback(){
    console.log('destroy');
  }


  FillProviderSelect2 = async function () {
    const info = await this.allReferences.self.ws.info();

    if (!info.providers.length) {
      this.providerDefault = null;
    }

    for (const provider of info.providers) {
      if (provider.name === "Windows CryptoAPI") {
        this.providerDefault = provider.id;
      }
    }
  };

  main = async function () {
    const allImportsWindow = allImports.bind(window);
    this.allReferences = allImportsWindow();

    this.allReferences.self.ws = new this.allReferences.WebcryptoSocket.SocketProvider({
      storage: await this.allReferences.WebcryptoSocket.BrowserStorage.create(),
    });
    this.allReferences.self.ws.connect("127.0.0.1:31337")
      .on("error", function (e) {
        console.error(e);
      })
      .on("listening", async (e) => {
        // Check if end-to-end session is approved
        if (!(await this.allReferences.self.ws.isLoggedIn())) {
          const pin = await this.allReferences.self.ws.challenge();
          // show PIN
          setTimeout(() => {
            alert("2key session PIN:" + pin);
          }, 100);
          // ask to approve session
          await this.allReferences.self.ws.login();
        }

        await this.FillData();

        // ws.cardReader.on("insert", updateProvider).on("remove", updateProvider);
      });
  };


  FillData = async function () {
    await this.FillProviderSelect2();
    const providerID = this.providerDefault;
    console.log(providerID);
  };


  fillCertificateSelect2 = async function (provider) {
    if (!(await provider.isLoggedIn())) {
      await provider.login();
    }

    let certIDs = await provider.certStorage.keys();
    certIDs = certIDs.filter((id) => {
      const parts = id.split("-");
      return parts[0] === "x509";
    });

    let keyIDs = await provider.keyStorage.keys();
    keyIDs = keyIDs.filter(function (id) {
      const parts = id.split("-");
      return parts[0] === "private";
    });

    const certs = [];
    for (const certID of certIDs) {
      for (const keyID of keyIDs) {
        if (keyID.split("-")[2] === certID.split("-")[2]) {
          try {
            const cert = await provider.certStorage.getItem(certID);

            certs.push({
              id: certID,
              item: cert,
            });
          } catch (e) {
            console.error(
              `Cannot get certificate ${certID} from CertificateStorage. ${e.message}`
            );
          }
        }
      }
    }
    this.certificate = certs.find((cert) =>
      cert.item._subjectName.includes("CN=" + this.cnData)
    );
    const certGenerated = this.certificate !== undefined;
    if (certGenerated) {
      this.certificate = this.certificate.id;
    } else {
      alert("Esta aplicación requiere el certificado de red eléctrica");
    }
    return certGenerated;
  };

  GetCertificateKey = async function (type, provider, certID) {
    const keyIDs = await provider.keyStorage.keys();
    for (const keyID of keyIDs) {
      const parts = keyID.split("-");

      if (parts[0] === type && parts[2] === certID.split("-")[2]) {
        const key = await provider.keyStorage.getItem(keyID);
        if (key) {
          return key;
        }
      }
    }
    if (type === "public") {
      const cert = await provider.certStorage.getItem(certID);
      if (cert) {
        return cert.publicKey;
      }
    }
    return null;
  };



  xmlSign = async (prov, dataSign = "") => {
    this.allReferences.XAdES.Application.setEngine("Fortify", prov);
    const xml = this.allReferences.XAdES.Parse(dataSign);
    var signedXml = new this.allReferences.XAdES.SignedXml();
    console.log(signedXml);

    var cert = await prov.certStorage.getItem(this.certificate);
    console.log(cert);
    const privateKey = await this.GetCertificateKey(
      "private",
      prov,
      this.certificate
    );
    console.log(privateKey);
    var certRawData = await prov.certStorage.exportCert("raw", cert);
    var x509 = this.allReferences.self.pvtsutils.Convert.ToBase64(certRawData);

    var signature = await signedXml.Sign(
      // Signing document
      cert.publicKey.algorithm.toAlgorithm(),
      privateKey, // key
      xml, // document
      {
        // options
        keyValue: cert.publicKey,
        x509: [x509],
        references: [{ hash: "SHA-1", transforms: ["enveloped"] }],
        signingCertificate: x509,
      }
    );

    console.log(signature.GetXml());
    const xmlValidation = new XMLSerializer().serializeToString(xml) !== this.messageBase.value;
    if(xmlValidation){
      alert('Formato XML no válido');
      this.signatureBase = '';
    }else{
      xml.documentElement.appendChild(signature.GetXml());
  
      this.signatureBase = new XMLSerializer().serializeToString(xml);

    }
    this.verificationBase = (!xmlValidation).toString();
  };

  signFunc = async () => {
    if (this.providerDefault) {
      const crypto = await this.allReferences.self.ws.getCrypto(this.providerDefault);
      const res = await this.fillCertificateSelect2(crypto);
      if (res) {
        console.log("sign");
        try {
          // Clear fields
          this.signatureBase = "";

          const provider = await this.allReferences.self.ws.getCrypto(this.providerDefault);
     
          if (this.typeSign.checked) {
            this.xmlSign(provider, this.messageBase.value);
          } else {
            const key = await this.GetCertificateKey(
              "private",
              provider,
              this.certificate
            );
            if (!key) {
              throw new Error("Certificate doesn't have private key");
            }

            const alg = {
              name: key.algorithm.name,
              hash: "SHA-256",
            };
            console.log(this.messageBase.value);
            const message = this.allReferences.self.pvtsutils.Convert.FromUtf8String(
              this.messageBase.value
            );
            const signature = await provider.subtle.sign(alg, key, message);
            this.signatureBase = this.allReferences.self.pvtsutils.Convert.ToHex(signature);
            console.log(this.signatureBase);
            const publicKey = await this.GetCertificateKey(
              "public",
              provider,
              this.certificate
            );

            const ok = await provider.subtle.verify(
              alg,
              publicKey,
              signature,
              message
            );
            this.verificationBase = ok.toString();
          }
        } finally {
        }
      }
    }
  };




  render() {
    return (
      <Host>
        <slot><div>
          <h2>Signing with a key via Fortify</h2>
          <div class="group">
            <label htmlFor="typeSign">XML:</label>
            <input id="typeSign" checked={true} type="checkbox" ref={(el) => this.typeSign = el as HTMLInputElement}/>
          </div>
          <div class="group">
            <label htmlFor="message">Message:</label>
            <textarea rows={10} ref={(el) => this.messageBase = el as HTMLTextAreaElement} id="message"></textarea>
          </div>
          <div class="group">
            <label htmlFor="signature">Signature(HEX):</label>
            <textarea rows={10} value={this.signatureBase} id="signature"></textarea>
          </div>
          <div class="group">
            <label>Verification:</label>
            <span id="verification">{this.verificationBase}</span>
          </div>
          <div class="group">
            <button onClick={() => this.signFunc()} id="sign">Sign</button>
          </div>
        </div></slot>
      </Host>
    );
  }

}
