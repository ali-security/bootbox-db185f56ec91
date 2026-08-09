//  Regression tests for CVE-2023-46998 - script injection through any of the
//  strings bootbox renders as HTML (dialog/alert/confirm message, dialog title,
//  button labels and the prompt checkbox/radio option text).
//
//  Every "attack" test proves the *outcome* - that the injected script never
//  runs - rather than a particular parser tree shape. Execution is detected
//  with the window.bootboxXssCanary global, which the payloads themselves set,
//  and by dispatching a real click through the DOM rather than a jQuery event.
describe('bootbox sanitization (CVE-2023-46998)', function() {
  'use strict';

  //  Fires as soon as jQuery parses the markup, so it needs no interaction
  var SCRIPT_PAYLOAD = '<script>window.bootboxXssCanary = \'script\';<\/script>';
  //  Fires when the user clicks anywhere inside the injected markup
  var CLICK_PAYLOAD = '<span id="bb-xss-click" onclick="window.bootboxXssCanary = \'onclick\';">click me</span>';
  //  Fires when the (deliberately broken) image fails to load
  var IMAGE_PAYLOAD = '<img id="bb-xss-img" src="bootbox-does-not-exist.png" onerror="window.bootboxXssCanary = \'onerror\';">';
  //  "javascript:" URLs on both an anchor and a form submission target
  var URL_PAYLOAD = '<a id="bb-xss-link" href="javascript:window.bootboxXssCanary = \'href\';">link</a>' +
    '<form id="bb-xss-form" action="javascript:window.bootboxXssCanary = \'action\';">' +
    '<button id="bb-xss-formaction" type="submit" formaction="javascript:window.bootboxXssCanary = \'formaction\';">go</button>' +
    '</form>';
  //  A form whose controls shadow the DOM members the sanitizer relies on
  var CLOBBER_PAYLOAD = '<form id="bb-xss-clobber" onclick="window.bootboxXssCanary = \'clobber\';">' +
    '<input name="attributes"><input name="removeAttribute"><input name="childNodes">' +
    '<input name="nodeName"><input name="removeChild"><input name="nodeType">' +
    '</form>';
  //  <img> inside <svg><style> is on the parser's foreign content breakout list
  var BREAKOUT_PAYLOAD = '<svg><style><img src="x" onerror="window.bootboxXssCanary = \'breakout\';"></style></svg>';

  function nativeClick(element) {
    if (typeof element.click === 'function') {
      element.click();
      return;
    }

    var event = document.createEvent('MouseEvents');
    event.initEvent('click', true, true);
    element.dispatchEvent(event);
  }

  beforeEach(function() {
    window.bootboxXssCanary = false;

    this.find = function(selector) {
      return this.dialog.find(selector);
    };

    //  Dispatch a genuine click on the given subtree, so that anything which
    //  survived sanitization gets a chance to run
    this.clickThrough = function(selector) {
      this.find(selector).find('*').addBack().each(function() {
        nativeClick(this);
      });
    };

    this.markup = function(selector) {
      return this.find(selector).html() || '';
    };
  });

  afterEach(function() {
    window.bootboxXssCanary = false;
    //  defaults are global; make sure a test which opted out cannot leak
    bootbox.setDefaults({sanitize: true});
  });


  //  Sanity check: the payloads really do execute when they are not sanitized.
  //  Without this, a green suite would not prove the sanitizer does anything.
  describe('the payloads used by these tests', function() {
    it('execute when sanitization is disabled', function() {
      this.dialog = bootbox.dialog({
        message: SCRIPT_PAYLOAD,
        sanitize: false
      });

      expect(window.bootboxXssCanary).to.equal('script');
    });

    it('execute on click when sanitization is disabled', function() {
      this.dialog = bootbox.dialog({
        message: CLICK_PAYLOAD,
        sanitize: false
      });

      expect(this.find('#bb-xss-click').length).to.equal(1);

      this.clickThrough('.bootbox-body');

      expect(window.bootboxXssCanary).to.equal('onclick');
    });
  });


  describe('the dialog message', function() {
    it('does not execute an injected script element', function() {
      this.dialog = bootbox.dialog({message: SCRIPT_PAYLOAD});

      expect(window.bootboxXssCanary).to.be.false;
      expect(this.find('script').length).to.equal(0);
      expect(this.markup('.bootbox-body')).to.not.contain('bootboxXssCanary');
    });

    it('does not execute an injected event handler attribute', function() {
      this.dialog = bootbox.dialog({message: CLICK_PAYLOAD});

      this.clickThrough('.bootbox-body');

      expect(window.bootboxXssCanary).to.be.false;
      expect(this.find('.bootbox-body [onclick]').length).to.equal(0);
      expect(this.markup('.bootbox-body')).to.not.contain('onclick');
    });

    it('strips the onerror handler from an injected image', function() {
      this.dialog = bootbox.dialog({message: IMAGE_PAYLOAD});

      expect(this.find('.bootbox-body [onerror]').length).to.equal(0);
      expect(this.markup('.bootbox-body')).to.not.contain('onerror');
    });

    //  NOTE: this payload is deliberately never clicked - the submit button
    //  would navigate the test runner away from the page. The security outcome
    //  is that no "javascript:" sink survives at all.
    it('strips "javascript:" URLs', function() {
      this.dialog = bootbox.dialog({message: URL_PAYLOAD});

      expect(window.bootboxXssCanary).to.be.false;
      expect(this.find('.bootbox-body [href]').length).to.equal(0);
      expect(this.find('.bootbox-body [action]').length).to.equal(0);
      expect(this.find('.bootbox-body [formaction]').length).to.equal(0);
      expect(this.markup('.bootbox-body')).to.not.contain('javascript:');
    });

    it('does not let a clobbered form smuggle an event handler through', function() {
      this.dialog = bootbox.dialog({message: CLOBBER_PAYLOAD});

      this.clickThrough('.bootbox-body');

      expect(window.bootboxXssCanary).to.be.false;
      expect(this.find('.bootbox-body [onclick]').length).to.equal(0);
      expect(this.markup('.bootbox-body')).to.not.contain('onclick');
    });

    it('does not let foreign content break out with its handlers intact', function() {
      this.dialog = bootbox.dialog({message: BREAKOUT_PAYLOAD});

      expect(window.bootboxXssCanary).to.be.false;
      expect(this.find('.bootbox-body svg').length).to.equal(0);
      expect(this.find('.bootbox-body style').length).to.equal(0);
      expect(this.find('.bootbox-body [onerror]').length).to.equal(0);
      expect(this.markup('.bootbox-body')).to.not.contain('onerror');
    });

    it('sanitizes the message given to bootbox.alert', function() {
      this.dialog = bootbox.alert(SCRIPT_PAYLOAD + CLICK_PAYLOAD);

      this.clickThrough('.bootbox-body');

      expect(window.bootboxXssCanary).to.be.false;
      expect(this.find('.bootbox-body [onclick]').length).to.equal(0);
    });

    it('sanitizes the message given to bootbox.confirm', function() {
      this.dialog = bootbox.confirm(SCRIPT_PAYLOAD + CLICK_PAYLOAD, function() {});

      this.clickThrough('.bootbox-body');

      expect(window.bootboxXssCanary).to.be.false;
      expect(this.find('.bootbox-body [onclick]').length).to.equal(0);
    });
  });


  describe('the dialog title', function() {
    it('does not execute an injected script element', function() {
      this.dialog = bootbox.dialog({
        message: 'safe',
        title: SCRIPT_PAYLOAD
      });

      expect(window.bootboxXssCanary).to.be.false;
      expect(this.find('.modal-title script').length).to.equal(0);
    });

    it('does not execute an injected event handler attribute', function() {
      this.dialog = bootbox.dialog({
        message: 'safe',
        title: CLICK_PAYLOAD
      });

      this.clickThrough('.modal-title');

      expect(window.bootboxXssCanary).to.be.false;
      expect(this.find('.modal-title [onclick]').length).to.equal(0);
      expect(this.markup('.modal-title')).to.not.contain('onclick');
    });
  });


  describe('a button label', function() {
    it('does not execute an injected script element', function() {
      this.dialog = bootbox.dialog({
        message: 'safe',
        buttons: {
          ok: {
            label: SCRIPT_PAYLOAD,
            callback: function() {}
          }
        }
      });

      expect(window.bootboxXssCanary).to.be.false;
      expect(this.find('.modal-footer script').length).to.equal(0);
    });

    it('does not keep an injected event handler attribute', function() {
      this.dialog = bootbox.dialog({
        message: 'safe',
        buttons: {
          ok: {
            label: CLICK_PAYLOAD,
            callback: function() {}
          }
        }
      });

      expect(this.find('.modal-footer [onclick]').length).to.equal(0);
      expect(this.markup('.modal-footer')).to.not.contain('onclick');
    });

    it('still renders a plain label', function() {
      this.dialog = bootbox.dialog({
        message: 'safe',
        buttons: {
          ok: {
            label: 'Custom OK',
            callback: function() {}
          }
        }
      });

      expect(this.find('.modal-footer button').text()).to.equal('Custom OK');
    });
  });


  describe('the prompt message', function() {
    it('does not execute an injected script element', function() {
      this.dialog = bootbox.prompt({
        title: 'safe',
        message: SCRIPT_PAYLOAD,
        callback: function() {}
      });

      expect(window.bootboxXssCanary).to.be.false;
      expect(this.find('.bootbox-prompt-message script').length).to.equal(0);
    });

    it('does not execute an injected event handler attribute', function() {
      this.dialog = bootbox.prompt({
        title: 'safe',
        message: CLICK_PAYLOAD,
        callback: function() {}
      });

      this.clickThrough('.bootbox-prompt-message');

      expect(window.bootboxXssCanary).to.be.false;
      expect(this.find('.bootbox-prompt-message [onclick]').length).to.equal(0);
      expect(this.markup('.bootbox-prompt-message')).to.not.contain('onclick');
    });

    it('still builds the form and its input', function() {
      this.dialog = bootbox.prompt({
        title: 'safe',
        message: 'Please enter a value',
        callback: function() {}
      });

      expect(this.find('form.bootbox-form').length).to.equal(1);
      expect(this.find('input.bootbox-input-text').length).to.equal(1);
      expect(this.find('.bootbox-prompt-message').text()).to.equal('Please enter a value');
    });
  });


  describe('a prompt checkbox option', function() {
    it('does not execute an injected script element', function() {
      this.dialog = bootbox.prompt({
        title: 'safe',
        inputType: 'checkbox',
        inputOptions: [
          {value: '1', text: SCRIPT_PAYLOAD}
        ],
        callback: function() {}
      });

      expect(window.bootboxXssCanary).to.be.false;
      expect(this.find('.bootbox-checkbox-list script').length).to.equal(0);
    });

    it('does not execute an injected event handler attribute', function() {
      this.dialog = bootbox.prompt({
        title: 'safe',
        inputType: 'checkbox',
        inputOptions: [
          {value: '1', text: CLICK_PAYLOAD}
        ],
        callback: function() {}
      });

      this.clickThrough('.bootbox-checkbox-list');

      expect(window.bootboxXssCanary).to.be.false;
      expect(this.find('.bootbox-checkbox-list [onclick]').length).to.equal(0);
      expect(this.markup('.bootbox-checkbox-list')).to.not.contain('onclick');
    });

    it('still renders plain option text', function() {
      this.dialog = bootbox.prompt({
        title: 'safe',
        inputType: 'checkbox',
        inputOptions: [
          {value: '1', text: 'Choice one'}
        ],
        callback: function() {}
      });

      expect($.trim(this.find('.bootbox-checkbox-list label').text())).to.equal('Choice one');
      expect(this.find('.bootbox-checkbox-list input[value="1"]').length).to.equal(1);
    });
  });


  describe('a prompt radio option', function() {
    it('does not execute an injected script element', function() {
      this.dialog = bootbox.prompt({
        title: 'safe',
        inputType: 'radio',
        inputOptions: [
          {value: '1', text: SCRIPT_PAYLOAD}
        ],
        callback: function() {}
      });

      expect(window.bootboxXssCanary).to.be.false;
      expect(this.find('.bootbox-radiobutton-list script').length).to.equal(0);
    });

    it('does not execute an injected event handler attribute', function() {
      this.dialog = bootbox.prompt({
        title: 'safe',
        inputType: 'radio',
        inputOptions: [
          {value: '1', text: CLICK_PAYLOAD}
        ],
        callback: function() {}
      });

      this.clickThrough('.bootbox-radiobutton-list');

      expect(window.bootboxXssCanary).to.be.false;
      expect(this.find('.bootbox-radiobutton-list [onclick]').length).to.equal(0);
      expect(this.markup('.bootbox-radiobutton-list')).to.not.contain('onclick');
    });

    it('still renders plain option text', function() {
      this.dialog = bootbox.prompt({
        title: 'safe',
        inputType: 'radio',
        inputOptions: [
          {value: '1', text: 'Choice one'}
        ],
        callback: function() {}
      });

      expect($.trim(this.find('.bootbox-radiobutton-list label').text())).to.equal('Choice one');
      expect(this.find('.bootbox-radiobutton-list input[value="1"]').length).to.equal(1);
    });
  });


  describe('the "sanitize" option', function() {
    it('leaves the content untouched when set to false for a single dialog', function() {
      this.dialog = bootbox.dialog({
        message: CLICK_PAYLOAD,
        sanitize: false
      });

      expect(this.find('#bb-xss-click').length).to.equal(1);
      expect(this.find('.bootbox-body [onclick]').length).to.equal(1);
    });

    it('leaves checkbox option text untouched when set to false for a single dialog', function() {
      this.dialog = bootbox.prompt({
        title: 'safe',
        inputType: 'checkbox',
        sanitize: false,
        inputOptions: [
          {value: '1', text: CLICK_PAYLOAD}
        ],
        callback: function() {}
      });

      expect(this.find('.bootbox-checkbox-list [onclick]').length).to.equal(1);
    });

    it('leaves the content untouched when disabled through setDefaults', function() {
      bootbox.setDefaults({sanitize: false});

      this.dialog = bootbox.dialog({message: CLICK_PAYLOAD});

      expect(this.find('#bb-xss-click').length).to.equal(1);
      expect(this.find('.bootbox-body [onclick]').length).to.equal(1);
    });

    it('sanitizes again once setDefaults re-enables it', function() {
      bootbox.setDefaults({sanitize: false});
      bootbox.setDefaults({sanitize: true});

      this.dialog = bootbox.dialog({message: CLICK_PAYLOAD});

      expect(this.find('.bootbox-body [onclick]').length).to.equal(0);
    });
  });


  describe('content which is not a string', function() {
    it('passes a jQuery object through untouched', function() {
      var node = $('<div class="from-jquery"><span onclick="window.bootboxXssCanary = \'jquery\';">x</span></div>');

      this.dialog = bootbox.dialog({message: node});

      expect(this.find('.from-jquery').length).to.equal(1);
      expect(this.find('.from-jquery [onclick]').length).to.equal(1);
    });
  });


  describe('safe content', function() {
    beforeEach(function() {
      this.dialog = bootbox.dialog({
        message:
          '<div class="wrapper" id="safe-wrapper">' +
          '<p>Hello <b>world</b> &amp; <i>everyone</i></p>' +
          '<a href="https://bootboxjs.com/" target="_blank" rel="noopener">a link</a>' +
          '<a href="/relative/path">a relative link</a>' +
          '<img src="https://bootboxjs.com/logo.png" alt="logo" width="10" height="10">' +
          '<ul><li>one</li><li>two</li></ul>' +
          '</div>'
      });
    });

    it('keeps the elements', function() {
      expect(this.find('#safe-wrapper').length).to.equal(1);
      expect(this.find('.bootbox-body b').text()).to.equal('world');
      expect(this.find('.bootbox-body i').text()).to.equal('everyone');
      expect(this.find('.bootbox-body li').length).to.equal(2);
      expect(this.find('.bootbox-body img').length).to.equal(1);
    });

    it('keeps safe attributes', function() {
      expect(this.find('.bootbox-body a[href="https://bootboxjs.com/"]').length).to.equal(1);
      expect(this.find('.bootbox-body a[href="/relative/path"]').length).to.equal(1);
      expect(this.find('.bootbox-body a[target="_blank"]').length).to.equal(1);
      expect(this.find('.bootbox-body img').attr('alt')).to.equal('logo');
    });

    it('keeps plain text intact', function() {
      this.dialog = bootbox.dialog({message: 'Hello & goodbye <3'});

      expect(this.find('.bootbox-body').text()).to.equal('Hello & goodbye <3');
    });
  });


  describe('custom form markup in the message', function() {
    beforeEach(function() {
      this.dialog = bootbox.dialog({
        message:
          '<form id="custom-form" action="/save" method="post">' +
          '<label for="custom-name">Name</label>' +
          '<input type="text" id="custom-name" name="name" value="bob" placeholder="your name" required>' +
          '<select name="choice"><option value="a">A</option><option value="b" selected>B</option></select>' +
          '<textarea name="notes" rows="3"></textarea>' +
          '<table><thead><tr><th scope="col">Header</th></tr></thead>' +
          '<tbody><tr><td colspan="2">Cell</td></tr></tbody></table>' +
          '</form>'
      });
    });

    it('keeps the form and its controls', function() {
      expect(this.find('#custom-form').length).to.equal(1);
      expect(this.find('#custom-form input[name="name"]').length).to.equal(1);
      expect(this.find('#custom-form select[name="choice"] option').length).to.equal(2);
      expect(this.find('#custom-form textarea[name="notes"]').length).to.equal(1);
      expect(this.find('#custom-form label[for="custom-name"]').length).to.equal(1);
    });

    it('keeps the control attributes bootbox users rely on', function() {
      expect(this.find('#custom-name').val()).to.equal('bob');
      expect(this.find('#custom-name').attr('placeholder')).to.equal('your name');
      expect(this.find('#custom-form').attr('action')).to.equal('/save');
      expect(this.find('#custom-form').attr('method')).to.equal('post');
    });

    it('keeps the table markup', function() {
      expect(this.find('#custom-form table th[scope="col"]').length).to.equal(1);
      expect(this.find('#custom-form table td[colspan="2"]').length).to.equal(1);
    });
  });
});
