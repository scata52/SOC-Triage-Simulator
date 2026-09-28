// The victim organisation is always one of Microsoft's documentation-reserved
// fictitious companies. They read as real, their domains are held for exactly
// this use, and no actual business is portrayed as breached. The same list
// supplies partners and vendors in mail/sign-in noise.

export interface FictitiousOrg {
  name: string;
  short: string; // used for host prefixes and NetBIOS
  domain: string;
  industry: string;
}

export const FICTITIOUS_ORGS: readonly FictitiousOrg[] = [
  { name: 'Contoso Ltd.', short: 'Contoso', domain: 'contoso.com', industry: 'Manufacturing' },
  { name: 'Fabrikam, Inc.', short: 'Fabrikam', domain: 'fabrikam.com', industry: 'Engineering services' },
  { name: 'Northwind Traders', short: 'Northwind', domain: 'northwindtraders.com', industry: 'Wholesale distribution' },
  { name: 'Woodgrove Bank', short: 'Woodgrove', domain: 'woodgrovebank.com', industry: 'Banking' },
  { name: 'Tailspin Toys', short: 'Tailspin', domain: 'tailspintoys.com', industry: 'Consumer goods' },
  { name: 'Litware, Inc.', short: 'Litware', domain: 'litwareinc.com', industry: 'Software' },
  { name: 'Proseware, Inc.', short: 'Proseware', domain: 'proseware.com', industry: 'Software' },
  { name: 'Adventure Works Cycles', short: 'AdvWorks', domain: 'adventure-works.com', industry: 'Retail' },
  { name: 'Alpine Ski House', short: 'Alpine', domain: 'alpineskihouse.com', industry: 'Hospitality' },
  { name: 'Lucerne Publishing', short: 'Lucerne', domain: 'lucernepublishing.com', industry: 'Publishing' },
  { name: 'Trey Research', short: 'Trey', domain: 'treyresearch.net', industry: 'Life sciences' },
  { name: 'Wide World Importers', short: 'WWI', domain: 'wideworldimporters.com', industry: 'Logistics' },
  { name: 'Humongous Insurance', short: 'Humongous', domain: 'humongousinsurance.com', industry: 'Insurance' },
  { name: 'Relecloud', short: 'Relecloud', domain: 'relecloud.com', industry: 'Cloud services' },
  { name: 'Coho Winery', short: 'Coho', domain: 'cohowinery.com', industry: 'Food and beverage' },
  { name: 'Fourth Coffee', short: 'Fourth', domain: 'fourthcoffee.com', industry: 'Food and beverage' },
  { name: "Margie's Travel", short: 'Margies', domain: 'margiestravel.com', industry: 'Travel' },
  { name: 'Blue Yonder Airlines', short: 'BlueYonder', domain: 'blueyonderairlines.com', industry: 'Aviation' },
  { name: 'City Power & Light', short: 'CPandL', domain: 'cpandl.com', industry: 'Utilities' },
  { name: 'Wingtip Toys', short: 'Wingtip', domain: 'wingtiptoys.com', industry: 'Consumer goods' },
];

export const FICTITIOUS_DOMAINS: ReadonlySet<string> = new Set(FICTITIOUS_ORGS.map((o) => o.domain));
