
// Description: Java 25 in-memory RAM DbIO implementation for ISOCcy.

/*
 *	server.markhome.mcf.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	These files are part of Mark's Code Fractal CFSec.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *	
 */

package server.markhome.mcf.v3_1.cfsec.cfsecram;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.time.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;

import server.markhome.mcf.v3_1.cfsec.cfsec.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.buff.*;
import server.markhome.mcf.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamISOCcyTable in-memory RAM DbIO implementation
 *	for ISOCcy.
 */
public class CFSecRamISOCcyTable
	implements ICFSecISOCcyTable
{
	private ICFSecSchema schema;
	private Map< Short,
				CFSecBuffISOCcy > dictByPKey
		= new HashMap< Short,
				CFSecBuffISOCcy >();
	private Map< CFSecBuffISOCcyByCcyCdIdxKey,
			CFSecBuffISOCcy > dictByCcyCdIdx
		= new HashMap< CFSecBuffISOCcyByCcyCdIdxKey,
			CFSecBuffISOCcy >();
	private Map< CFSecBuffISOCcyByCcyNmIdxKey,
			CFSecBuffISOCcy > dictByCcyNmIdx
		= new HashMap< CFSecBuffISOCcyByCcyNmIdxKey,
			CFSecBuffISOCcy >();

	public CFSecRamISOCcyTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffISOCcy ensureRec(ICFSecISOCcy rec) {
		if (rec == null) {
			return( null );
		}
		else {
			int classCode = rec.getClassCode();
			if (classCode == ICFSecISOCcy.CLASS_CODE) {
				return( ((CFSecBuffISOCcyDefaultFactory)(schema.getFactoryISOCcy())).ensureRec((ICFSecISOCcy)rec) );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), "ensureRec", "rec", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecISOCcy createISOCcy( ICFSecAuthorization Authorization,
		ICFSecISOCcy iBuff )
	{
		final String S_ProcName = "createISOCcy";
		
		CFSecBuffISOCcy Buff = (CFSecBuffISOCcy)ensureRec(iBuff);
		Short pkey;
		pkey = schema.nextISOCcyIdGen();
		Buff.setRequiredISOCcyId( pkey );
		CFSecBuffISOCcyByCcyCdIdxKey keyCcyCdIdx = (CFSecBuffISOCcyByCcyCdIdxKey)schema.getFactoryISOCcy().newByCcyCdIdxKey();
		keyCcyCdIdx.setRequiredISOCode( Buff.getRequiredISOCode() );

		CFSecBuffISOCcyByCcyNmIdxKey keyCcyNmIdx = (CFSecBuffISOCcyByCcyNmIdxKey)schema.getFactoryISOCcy().newByCcyNmIdxKey();
		keyCcyNmIdx.setRequiredName( Buff.getRequiredName() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByCcyCdIdx.containsKey( keyCcyCdIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"ISOCcyCodeIdx",
				"ISOCcyCodeIdx",
				keyCcyCdIdx );
		}

		if( dictByCcyNmIdx.containsKey( keyCcyNmIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"ISOCcyNameIdx",
				"ISOCcyNameIdx",
				keyCcyNmIdx );
		}

		// Validate foreign keys

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		dictByCcyCdIdx.put( keyCcyCdIdx, Buff );

		dictByCcyNmIdx.put( keyCcyNmIdx, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecISOCcy.CLASS_CODE) {
				CFSecBuffISOCcy retbuff = ((CFSecBuffISOCcy)(schema.getFactoryISOCcy().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecISOCcy readDerived( ICFSecAuthorization Authorization,
		Short PKey )
	{
		final String S_ProcName = "CFSecRamISOCcy.readDerived";
		ICFSecISOCcy buff;
		if( PKey == null ) {
			return( null );
		}
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecISOCcy lockDerived( ICFSecAuthorization Authorization,
		Short PKey )
	{
		final String S_ProcName = "CFSecRamISOCcy.lockDerived";
		ICFSecISOCcy buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecISOCcy[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamISOCcy.readAllDerived";
		ICFSecISOCcy[] retList = new ICFSecISOCcy[ dictByPKey.values().size() ];
		Iterator< CFSecBuffISOCcy > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	@Override
	public ICFSecISOCcy readDerivedByCcyCdIdx( ICFSecAuthorization Authorization,
		String ISOCode )
	{
		final String S_ProcName = "CFSecRamISOCcy.readDerivedByCcyCdIdx";
		CFSecBuffISOCcyByCcyCdIdxKey key = (CFSecBuffISOCcyByCcyCdIdxKey)schema.getFactoryISOCcy().newByCcyCdIdxKey();

		key.setRequiredISOCode( ISOCode );
		ICFSecISOCcy buff;
		if( dictByCcyCdIdx.containsKey( key ) ) {
			buff = dictByCcyCdIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecISOCcy readDerivedByCcyNmIdx( ICFSecAuthorization Authorization,
		String Name )
	{
		final String S_ProcName = "CFSecRamISOCcy.readDerivedByCcyNmIdx";
		CFSecBuffISOCcyByCcyNmIdxKey key = (CFSecBuffISOCcyByCcyNmIdxKey)schema.getFactoryISOCcy().newByCcyNmIdxKey();

		key.setRequiredName( Name );
		ICFSecISOCcy buff;
		if( dictByCcyNmIdx.containsKey( key ) ) {
			buff = dictByCcyNmIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecISOCcy readDerivedByIdIdx( ICFSecAuthorization Authorization,
		short ISOCcyId )
	{
		final String S_ProcName = "CFSecRamISOCcy.readDerivedByIdIdx() ";
		ICFSecISOCcy buff;
		if( dictByPKey.containsKey( ISOCcyId ) ) {
			buff = dictByPKey.get( ISOCcyId );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecISOCcy readRec( ICFSecAuthorization Authorization,
		Short PKey )
	{
		final String S_ProcName = "CFSecRamISOCcy.readRec";
		ICFSecISOCcy buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecISOCcy.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecISOCcy lockRec( ICFSecAuthorization Authorization,
		Short PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecISOCcy buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecISOCcy.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecISOCcy[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamISOCcy.readAllRec";
		ICFSecISOCcy buff;
		ArrayList<ICFSecISOCcy> filteredList = new ArrayList<ICFSecISOCcy>();
		ICFSecISOCcy[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecISOCcy.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecISOCcy[0] ) );
	}

	@Override
	public ICFSecISOCcy readRecByIdIdx( ICFSecAuthorization Authorization,
		short ISOCcyId )
	{
		final String S_ProcName = "CFSecRamISOCcy.readRecByIdIdx() ";
		ICFSecISOCcy buff = readDerivedByIdIdx( Authorization,
			ISOCcyId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecISOCcy.CLASS_CODE ) ) {
			return( (ICFSecISOCcy)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecISOCcy readRecByCcyCdIdx( ICFSecAuthorization Authorization,
		String ISOCode )
	{
		final String S_ProcName = "CFSecRamISOCcy.readRecByCcyCdIdx() ";
		ICFSecISOCcy buff = readDerivedByCcyCdIdx( Authorization,
			ISOCode );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecISOCcy.CLASS_CODE ) ) {
			return( (ICFSecISOCcy)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecISOCcy readRecByCcyNmIdx( ICFSecAuthorization Authorization,
		String Name )
	{
		final String S_ProcName = "CFSecRamISOCcy.readRecByCcyNmIdx() ";
		ICFSecISOCcy buff = readDerivedByCcyNmIdx( Authorization,
			Name );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecISOCcy.CLASS_CODE ) ) {
			return( (ICFSecISOCcy)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecISOCcy updateISOCcy( ICFSecAuthorization Authorization,
		ICFSecISOCcy iBuff )
	{
		CFSecBuffISOCcy Buff = (CFSecBuffISOCcy)ensureRec(iBuff);
		Short pkey = Buff.getPKey();
		CFSecBuffISOCcy existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateISOCcy",
				"Existing record not found",
				"Existing record not found",
				"ISOCcy",
				"ISOCcy",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateISOCcy",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffISOCcyByCcyCdIdxKey existingKeyCcyCdIdx = (CFSecBuffISOCcyByCcyCdIdxKey)schema.getFactoryISOCcy().newByCcyCdIdxKey();
		existingKeyCcyCdIdx.setRequiredISOCode( existing.getRequiredISOCode() );

		CFSecBuffISOCcyByCcyCdIdxKey newKeyCcyCdIdx = (CFSecBuffISOCcyByCcyCdIdxKey)schema.getFactoryISOCcy().newByCcyCdIdxKey();
		newKeyCcyCdIdx.setRequiredISOCode( Buff.getRequiredISOCode() );

		CFSecBuffISOCcyByCcyNmIdxKey existingKeyCcyNmIdx = (CFSecBuffISOCcyByCcyNmIdxKey)schema.getFactoryISOCcy().newByCcyNmIdxKey();
		existingKeyCcyNmIdx.setRequiredName( existing.getRequiredName() );

		CFSecBuffISOCcyByCcyNmIdxKey newKeyCcyNmIdx = (CFSecBuffISOCcyByCcyNmIdxKey)schema.getFactoryISOCcy().newByCcyNmIdxKey();
		newKeyCcyNmIdx.setRequiredName( Buff.getRequiredName() );

		// Check unique indexes

		if( ! existingKeyCcyCdIdx.equals( newKeyCcyCdIdx ) ) {
			if( dictByCcyCdIdx.containsKey( newKeyCcyCdIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateISOCcy",
					"ISOCcyCodeIdx",
					"ISOCcyCodeIdx",
					newKeyCcyCdIdx );
			}
		}

		if( ! existingKeyCcyNmIdx.equals( newKeyCcyNmIdx ) ) {
			if( dictByCcyNmIdx.containsKey( newKeyCcyNmIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateISOCcy",
					"ISOCcyNameIdx",
					"ISOCcyNameIdx",
					newKeyCcyNmIdx );
			}
		}

		// Validate foreign keys

		// Update is valid

		Map< Short, CFSecBuffISOCcy > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		dictByCcyCdIdx.remove( existingKeyCcyCdIdx );
		dictByCcyCdIdx.put( newKeyCcyCdIdx, Buff );

		dictByCcyNmIdx.remove( existingKeyCcyNmIdx );
		dictByCcyNmIdx.put( newKeyCcyNmIdx, Buff );

		return(Buff);
	}

	@Override
	public void deleteISOCcy( ICFSecAuthorization Authorization,
		ICFSecISOCcy iBuff )
	{
		final String S_ProcName = "CFSecRamISOCcyTable.deleteISOCcy() ";
		CFSecBuffISOCcy Buff = (CFSecBuffISOCcy)ensureRec(iBuff);
		int classCode;
		Short pkey = (Short)(Buff.getPKey());
		CFSecBuffISOCcy existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteISOCcy",
				pkey );
		}
		// Short circuit self-referential code to prevent stack overflows
		Object arrCheckISOCcyCountries[] = schema.getTableISOCtryCcy().readDerivedByCcyIdx( Authorization,
						existing.getRequiredISOCcyId() );
		if( arrCheckISOCcyCountries.length > 0 ) {
			schema.getTableISOCtryCcy().deleteISOCtryCcyByCcyIdx( Authorization,
						existing.getRequiredISOCcyId() );
		}
		CFSecBuffISOCcyByCcyCdIdxKey keyCcyCdIdx = (CFSecBuffISOCcyByCcyCdIdxKey)schema.getFactoryISOCcy().newByCcyCdIdxKey();
		keyCcyCdIdx.setRequiredISOCode( existing.getRequiredISOCode() );

		CFSecBuffISOCcyByCcyNmIdxKey keyCcyNmIdx = (CFSecBuffISOCcyByCcyNmIdxKey)schema.getFactoryISOCcy().newByCcyNmIdxKey();
		keyCcyNmIdx.setRequiredName( existing.getRequiredName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< Short, CFSecBuffISOCcy > subdict;

		dictByPKey.remove( pkey );

		dictByCcyCdIdx.remove( keyCcyCdIdx );

		dictByCcyNmIdx.remove( keyCcyNmIdx );

	}
	@Override
	public void deleteISOCcyByIdIdx( ICFSecAuthorization Authorization,
		Short argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffISOCcy cur;
		LinkedList<CFSecBuffISOCcy> matchSet = new LinkedList<CFSecBuffISOCcy>();
		Iterator<CFSecBuffISOCcy> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffISOCcy> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffISOCcy)(schema.getTableISOCcy().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOCcyId() ));
			deleteISOCcy( Authorization, cur );
		}
	}

	@Override
	public void deleteISOCcyByCcyCdIdx( ICFSecAuthorization Authorization,
		String argISOCode )
	{
		CFSecBuffISOCcyByCcyCdIdxKey key = (CFSecBuffISOCcyByCcyCdIdxKey)schema.getFactoryISOCcy().newByCcyCdIdxKey();
		key.setRequiredISOCode( argISOCode );
		deleteISOCcyByCcyCdIdx( Authorization, key );
	}

	@Override
	public void deleteISOCcyByCcyCdIdx( ICFSecAuthorization Authorization,
		ICFSecISOCcyByCcyCdIdxKey argKey )
	{
		CFSecBuffISOCcy cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffISOCcy> matchSet = new LinkedList<CFSecBuffISOCcy>();
		Iterator<CFSecBuffISOCcy> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffISOCcy> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffISOCcy)(schema.getTableISOCcy().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOCcyId() ));
			deleteISOCcy( Authorization, cur );
		}
	}

	@Override
	public void deleteISOCcyByCcyNmIdx( ICFSecAuthorization Authorization,
		String argName )
	{
		CFSecBuffISOCcyByCcyNmIdxKey key = (CFSecBuffISOCcyByCcyNmIdxKey)schema.getFactoryISOCcy().newByCcyNmIdxKey();
		key.setRequiredName( argName );
		deleteISOCcyByCcyNmIdx( Authorization, key );
	}

	@Override
	public void deleteISOCcyByCcyNmIdx( ICFSecAuthorization Authorization,
		ICFSecISOCcyByCcyNmIdxKey argKey )
	{
		CFSecBuffISOCcy cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffISOCcy> matchSet = new LinkedList<CFSecBuffISOCcy>();
		Iterator<CFSecBuffISOCcy> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffISOCcy> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffISOCcy)(schema.getTableISOCcy().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOCcyId() ));
			deleteISOCcy( Authorization, cur );
		}
	}
}
