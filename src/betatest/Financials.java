/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package betatest;

/**
 *
 * @author Administrator
 */
    
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.text.ParseException;
    
public class Financials {
    private static final NumberFormat nfPercent;
    private static final NumberFormat nfCurrency;
    
    static {
    
        // establish percentage formatter.
        nfPercent = NumberFormat.getPercentInstance();
        nfPercent.setMinimumFractionDigits(2);
        nfPercent.setMaximumFractionDigits(4);
    
        // establish currency formatter.
        nfCurrency = NumberFormat.getCurrencyInstance();
        nfCurrency.setMinimumFractionDigits(2);
        nfCurrency.setMaximumFractionDigits(2);
    }
    
    /**
     * Format passed number value to appropriate monetary string for display.
     * 
     * @param number
     * @return localized currency string (e.g., "$1,092.20").
     */
    public static String formatCurrency(double number) {
        return nfCurrency.format(number);
    }
    
    /**
     * Format passed number value to percent string for display.
     * 
     * @param number
     * @return percentage string (e.g., "7.00%").
     */
    public static String formatPercent(double number) {
        return nfPercent.format(number);
    }
    
    /**
     * Convert passed string to numerical percent for use in calculations.
     * 
     * @param s
     * @return <code>double</code> representing percentage as a decimal.
     * @throws ParseException
     *             if string is not a valid representation of a percent.
     */
    public static double stringToPercent(String s) throws ParseException {
        return nfPercent.parse(s).doubleValue();
    }
    
    /**
     * Emulates Excel/Calc's PMT(interest_rate, number_payments, PV, FV, Type)
     * function, which calculates the mortgage or annuity payment / yield per
     * period.
     * 
     * @param r
     *            - periodic interest rate represented as a decimal.
     * @param nper
     *            - number of total payments / periods.
     * @param pv
     *            - present value -- borrowed or invested principal.
     * @param fv
     *            - future value of loan or annuity.
     * @param type
     *            - when payment is made: beginning of period is 1; end, 0.
     * @return <code>double</code> representing periodic payment amount.
     */
    public static double pmt(double r, int nper, double pv, double fv, int type) {
    
        // pmt = r / ((1 + r)^N - 1) * -(pv * (1 + r)^N + fv)
        double pmt = r / (Math.pow(1 + r, nper) - 1)
                * -(pv * Math.pow(1 + r, nper) + fv);
    
        // account for payments at beginning of period versus end.
        if (type == 1)
            pmt /= (1 + r);
    
        // return results to caller.
        return pmt;
    }
    
    /**
     * Overloaded pmt() call omitting type, which defaults to 0.
     * 
     * @see #pmt(double, int, double, double, int)
     */
    public static double pmt(double r, int nper, double pv, double fv) {
        return pmt(r, nper, pv, fv, 0);
    }
    
    /**
     * Overloaded pmt() call omitting fv and type, which both default to 0.
     * 
     * @see #pmt(double, int, double, double, int)
     */
    public static double pmt(double r, int nper, double pv) {
        return pmt(r, nper, pv, 0);
    }
    
    /**
     * Emulates Excel/Calc's FV(interest_rate, number_payments, payment, PV,
     * Type) function, which calculates future value or principal at period N.
     * 
     * @param r
     *            - periodic interest rate represented as a decimal.
     * @param nper
     *            - number of total payments / periods.
     * @param c
     *            - periodic payment amount.
     * @param pv
     *            - present value -- borrowed or invested principal.
     * @param type
     *            - when payment is made: beginning of period is 1; end, 0.
     * @return <code>double</code> representing future principal value.
     */
    public static double fv(double r, int nper, double c, double pv, int type) {
    
        // account for payments at beginning of period versus end.
        // since we are going in reverse, we multiply by 1 plus interest rate.
        if (type == 1)
            c *= (1 + r);
    
        // fv = -(((1 + r)^N - 1) / r * c + pv * (1 + r)^N);
        double fv = -((Math.pow(1 + r, nper) - 1) / r * c + pv
                * Math.pow(1 + r, nper));
    
        // return results to caller.
        return fv;
    }
    
    /**
     * Overloaded fv() call omitting type, which defaults to 0.
     * 
     * @see #fv(double, int, double, double, int)
     */
    public static double fv(double r, int nper, double c, double pv) {
        return fv(r, nper, c, pv);
    }
    
    /**
     * Emulates Excel/Calc's IPMT(interest_rate, period, number_payments, PV,
     * FV, Type) function, which calculates the portion of the payment at a
     * given period that is the interest on previous balance.
     * 
     * @param r
     *            - periodic interest rate represented as a decimal.
     * @param per
     *            - period (payment number) to check value at.
     * @param nper
     *            - number of total payments / periods.
     * @param pv
     *            - present value -- borrowed or invested principal.
     * @param fv
     *            - future value of loan or annuity.
     * @param type
     *            - when payment is made: beginning of period is 1; end, 0.
     * @return <code>double</code> representing interest portion of payment.
     * 
     * @see #pmt(double, int, double, double, int)
     * @see #fv(double, int, double, double, int)
     */
    public static double ipmt(double r, int per, int nper, double pv,
            double fv, int type) {
    
        // Prior period (i.e., per-1) balance times periodic interest rate.
        // i.e., ipmt = fv(r, per-1, c, pv, type) * r
        // where c = pmt(r, nper, pv, fv, type)
        double ipmt = fv(r, per - 1, pmt(r, nper, pv, fv, type), pv, type) * r;
    
        // account for payments at beginning of period versus end.
        if (type == 1)
            ipmt /= (1 + r);
    
        // return results to caller.
        return ipmt;
    }
    
    /**
     * Emulates Excel/Calc's PPMT(interest_rate, period, number_payments, PV,
     * FV, Type) function, which calculates the portion of the payment at a
     * given period that will apply to principal.
     * 
     * @param r
     *            - periodic interest rate represented as a decimal.
     * @param per
     *            - period (payment number) to check value at.
     * @param nper
     *            - number of total payments / periods.
     * @param pv
     *            - present value -- borrowed or invested principal.
     * @param fv
     *            - future value of loan or annuity.
     * @param type
     *            - when payment is made: beginning of period is 1; end, 0.
     * @return <code>double</code> representing principal portion of payment.
     * 
     * @see #pmt(double, int, double, double, int)
     * @see #ipmt(double, int, int, double, double, int)
     */
    public static double ppmt(double r, int per, int nper, double pv,
            double fv, int type) {
    
        // Calculated payment per period minus interest portion of that period.
        // i.e., ppmt = c - i
        // where c = pmt(r, nper, pv, fv, type)
        // and i = ipmt(r, per, nper, pv, fv, type)
        return pmt(r, nper, pv, fv, type) - ipmt(r, per, nper, pv, fv, type);
    }

    public static void main(String[] args) {
        int startyear = 2014;
        int startmonth = 8;
        double r = 0.101/12;
        int period = 0;
        int tenure = 12;
        int nper = 12*tenure;
        double pv = 1900000;
        double fv = 0;
        int type = 0;
        double ympmt = 0;
        double yipmt = 0;
        double yppmt = 0;
        double tmpmt = 0;
        double tipmt = 0;
        double tppmt = 0;
        
        DecimalFormat df = new DecimalFormat("##.00");

        for (int year=1; year <= tenure; year++) {
            ympmt = 0;
            yipmt = 0;
            yppmt = 0;
            for (int month=1; month <= 12; month++) {
                period = (year-1)*12 + month;
                double mpmt = pmt(r, nper, pv, fv, type);
                double ipmt = ipmt(r, period, nper, pv, fv, type);
                double ppmt = ppmt(r, period, nper, pv, fv, type);
                
                ympmt += mpmt;
                yipmt += ipmt;
                yppmt += ppmt;

                tmpmt += mpmt;
                tipmt += ipmt;
                tppmt += ppmt;

//                System.out.println(Integer.toString(period)+" ==> "+df.format(mpmt)+" = "+df.format(ppmt)+" + "+df.format(ipmt));
            }
                System.out.println(Integer.toString(year)+" ==> "+df.format(ympmt)+" = "+df.format(yppmt)+" + "+df.format(yipmt));
        }
                System.out.println("Totals:"+" ==> "+df.format(tmpmt)+" = "+df.format(tppmt)+" + "+df.format(tipmt));
    }
}