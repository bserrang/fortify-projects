import { newE2EPage } from '@stencil/core/testing';

describe('fortify-sign', () => {
  it('renders', async () => {
    const page = await newE2EPage();
    await page.setContent('<fortify-sign></fortify-sign>');

    const element = await page.find('fortify-sign');
    expect(element).toHaveClass('hydrated');
  });
});
