import { newSpecPage } from '@stencil/core/testing';
import { FortifySign } from '../fortify-sign';

describe('fortify-sign', () => {
  it('renders', async () => {
    const page = await newSpecPage({
      components: [FortifySign],
      html: `<fortify-sign></fortify-sign>`,
    });
    expect(page.root).toEqualHtml(`
      <fortify-sign>
        <mock:shadow-root>
          <slot></slot>
        </mock:shadow-root>
      </fortify-sign>
    `);
  });
});
